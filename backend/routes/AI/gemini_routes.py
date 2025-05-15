# backend/routes/AI/gemini_routes.py
import json
import logging
import os
from flask import Blueprint, request, jsonify, current_app, g
from bson.objectid import ObjectId
import time
from flask import stream_with_context, Response
import time
import threading

from middleware.subscription_check import subscription_required
from helpers.gemini_helper import gemini_helper
from models.test import get_user_by_id
from helpers.ai_guard import apply_ai_guardrails
from helpers.rate_limiter import rate_limit
from helpers.jwt_auth import jwt_required_wrapper

portfolio_bp = Blueprint('portfolio', __name__)
logger = logging.getLogger(__name__)


generation_tasks = {}

@portfolio_bp.route('/generate-stream', methods=['POST'])
@jwt_required_wrapper
@rate_limit('portfolio') 
def generate_portfolio_stream():
    """
    Generate a portfolio website with streaming updates to client
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request format"}), 400
        
        user_id = g.user_id
        resume_text = data.get('resume_text')
        preferences = data.get('preferences', {})
        
        if not resume_text:
            return jsonify({"error": "Resume text is required"}), 400
        
        # Apply AI guardrails
        proceed, sanitized_resume, message = apply_ai_guardrails(resume_text, 'portfolio', user_id)
        if not proceed:
            return jsonify({"error": message}), 422
        
        # Initialize task status
        generation_tasks[user_id] = {
            "status": "pending",
            "started_at": time.time(),
            "error": None,
            "portfolio_id": None
        }
        
        logger.info(f"Starting portfolio generation for user {user_id} with {len(sanitized_resume)} chars of resume")
        
        # Initialize portfolio generation in a background thread
        def generate_portfolio_task():
            try:
                # Get user info
                user = get_user_by_id(user_id)
                if not user:
                    logger.error(f"User {user_id} not found")
                    generation_tasks[user_id]["status"] = "failed"
                    generation_tasks[user_id]["error"] = "User not found"
                    return
                
                # Generate components with retries
                portfolio_components = None
                max_retries = 3
                for attempt in range(max_retries):
                    try:
                        # Try to generate portfolio
                        portfolio_components = gemini_helper.generate_portfolio(sanitized_resume, preferences)
                        break
                    except Exception as e:
                        logger.error(f"Generation attempt {attempt+1} failed: {str(e)}")
                        if attempt == max_retries - 1:
                            logger.error(f"All attempts failed for user {user_id}")
                            generation_tasks[user_id]["status"] = "failed"
                            generation_tasks[user_id]["error"] = f"Generation failed after {max_retries} attempts: {str(e)}"
                            return
                        # Wait before retrying
                        time.sleep(2 ** attempt)  # Exponential backoff
                
                if portfolio_components:
                    # Check for minimum required components
                    required_files = ['public/index.html', 'src/index.js', 'src/App.js']
                    missing_files = [f for f in required_files if f not in portfolio_components]
                    
                    if missing_files:
                        logger.error(f"Generated portfolio missing required files: {missing_files}")
                        generation_tasks[user_id]["status"] = "failed"
                        generation_tasks[user_id]["error"] = f"Generated portfolio missing required files: {missing_files}"
                        return
                    
                    # Save to database once generation succeeds
                    portfolio_id = save_portfolio(user_id, portfolio_components, preferences, resume_text)
                    logger.info(f"Portfolio {portfolio_id} successfully generated and saved")
                    
                    # Update task status
                    generation_tasks[user_id]["status"] = "completed"
                    generation_tasks[user_id]["portfolio_id"] = str(portfolio_id)
                    generation_tasks[user_id]["completed_at"] = time.time()
                else:
                    logger.error(f"Empty portfolio components returned for user {user_id}")
                    generation_tasks[user_id]["status"] = "failed"
                    generation_tasks[user_id]["error"] = "Portfolio generation returned empty components"
                
            except Exception as e:
                logger.exception(f"Background task error: {str(e)}")
                generation_tasks[user_id]["status"] = "failed"
                generation_tasks[user_id]["error"] = str(e)

        # Start background task
        thread = threading.Thread(target=generate_portfolio_task)
        thread.daemon = True
        thread.start()
        
        # Send immediate success response to client
        return jsonify({
            "success": True,
            "message": "Portfolio generation started",
            "status": "processing"
        })
        
    except Exception as e:
        logger.exception(f"Error starting portfolio generation: {str(e)}")
        return jsonify({"error": "Failed to start portfolio generation. Please try again."}), 500


@portfolio_bp.route('/status/generation', methods=['GET'])
@jwt_required_wrapper
@rate_limit('portfolio')
def get_generation_status():
    """Check if the user has any recently generated portfolios"""
    user_id = g.user_id
    
    try:
        # First, check the in-memory task tracker
        if user_id in generation_tasks:
            task = generation_tasks[user_id]
            
            # If task is completed, return the portfolio ID
            if task["status"] == "completed":
                logger.info(f"Returning completed status for user {user_id}, portfolio {task['portfolio_id']}")
                return jsonify({
                    "success": True,
                    "status": "completed",
                    "portfolio_id": task["portfolio_id"],
                    "duration": time.time() - task["started_at"]
                })
            
            # If task failed, return the error
            elif task["status"] == "failed":
                logger.info(f"Returning failed status for user {user_id}: {task['error']}")
                return jsonify({
                    "success": False,
                    "status": "failed",
                    "error": task["error"],
                    "duration": time.time() - task["started_at"]
                })
            
            # Task is still in progress
            else:
                duration = time.time() - task["started_at"]
                logger.info(f"Generation still in progress for user {user_id} ({duration:.1f}s)")
                return jsonify({
                    "success": False,
                    "status": "pending",
                    "duration": duration
                })
        
        # If not in task tracker, check the database (fallback for server restarts)
        # Look for portfolios created in the last 10 minutes
        cutoff_time = time.time() - (10 * 60)  # 10 minutes ago
        
        from mongodb.database import db
        
        # Debug: Log query parameters
        logger.debug(f"Searching for recent portfolio with user_id: {user_id}, cutoff_time: {cutoff_time}")
        
        recent_portfolio = db.portfolios.find_one({
            "user_id": ObjectId(user_id),
            "created_at": {"$gt": cutoff_time}
        }, sort=[("created_at", -1)])
        
        # Add debug logging to see if portfolio exists
        if recent_portfolio:
            # Convert ObjectIds to strings
            portfolio_id = str(recent_portfolio["_id"])
            
            logger.info(f"Found recent portfolio for user {user_id} in database: {portfolio_id}")
            
            # Log component count for debugging
            component_count = len(recent_portfolio.get("components", {}))
            logger.debug(f"Portfolio components count: {component_count}")
            
            # Add this portfolio to the task tracker to avoid future DB lookups
            generation_tasks[user_id] = {
                "status": "completed",
                "portfolio_id": portfolio_id,
                "started_at": recent_portfolio.get("created_at", time.time() - 60),
                "completed_at": time.time()
            }
            
            return jsonify({
                "success": True,
                "status": "completed",
                "portfolio_id": portfolio_id,
                "components_count": component_count
            })
        else:
            logger.info(f"No recent portfolios found for user {user_id}")
            return jsonify({
                "success": False,
                "status": "pending" 
            })
    except Exception as e:
        logger.error(f"Error checking generation status: {str(e)}")
        return jsonify({
            "success": False,
            "status": "error",
            "message": f"Failed to check generation status: {str(e)}"
        }), 500

@portfolio_bp.route('/fix-error', methods=['POST'])
@jwt_required_wrapper
@rate_limit('fix-error')
def fix_portfolio_error():
    """
    Fix errors in generated portfolio code
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request format"}), 400
        
        user_id = g.user_id
        portfolio_id = data.get('portfolio_id')
        component_path = data.get('component_path')
        error_message = data.get('error_message')
        
        if not all([portfolio_id, component_path, error_message]):
            return jsonify({"error": "Missing required fields"}), 400
        
        # Get the portfolio from the database
        portfolio = get_portfolio(user_id, portfolio_id)
        if not portfolio:
            return jsonify({"error": "Portfolio not found"}), 404
        
        # Get the component code with error
        component_code = portfolio.get('components', {}).get(component_path)
        if not component_code:
            return jsonify({"error": f"Component {component_path} not found"}), 404
        
        # Get the original resume and preferences
        resume_text = portfolio.get('resume_text', '')
        preferences = portfolio.get('preferences', {})
        
        logger.info(f"Attempting to fix error in {component_path} for portfolio {portfolio_id}")
        
        # Fix the error
        fixed_code = gemini_helper.fix_portfolio_error(
            error_message, component_code, resume_text, preferences)
        
        # Update the portfolio in the database
        update_portfolio_component(user_id, portfolio_id, component_path, fixed_code)
        
        logger.info(f"Successfully fixed error in {component_path}")
        
        return jsonify({
            "success": True,
            "component_path": component_path,
            "fixed_code": fixed_code
        })
        
    except Exception as e:
        logger.exception(f"Error fixing portfolio: {str(e)}")
        return jsonify({"error": f"Failed to fix portfolio: {str(e)}"}), 500

@portfolio_bp.route('/deploy', methods=['POST'])
@jwt_required_wrapper
def deploy_portfolio():  # Remove the async keyword
    """
    Deploy a portfolio to Vercel
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request format"}), 400
        
        user_id = g.user_id
        portfolio_id = data.get('portfolio_id')
        vercel_token = data.get('vercel_token')
        use_oauth = data.get('use_oauth', False)
        
        # If using OAuth, get GitHub token from session
        if use_oauth:
            github_token = session.get('github_token')
            if not github_token:
                return jsonify({"error": "No GitHub token found in session. Please authorize with GitHub first."}), 400
        else:
            # Otherwise use manually provided token
            github_token = data.get('github_token')
        
        if not all([portfolio_id, github_token, vercel_token]):
            return jsonify({"error": "Missing required fields"}), 400
        
        # Get the portfolio from the database
        portfolio = get_portfolio(user_id, portfolio_id)
        if not portfolio:
            return jsonify({"error": "Portfolio not found"}), 404
        
        # Deploy to Vercel
        from utils.deployment_service import deployment_service
        
        deployment_result = deployment_service.deploy_to_vercel_sync(
            user_id, 
            portfolio_id, 
            github_token, 
            vercel_token,
            portfolio.get('components', {})
        )
        
        # Update the portfolio with deployment info
        update_portfolio_deployment(
            user_id, 
            portfolio_id, 
            deployment_result['deployment_url'],
            deployment_result['github_repo']
        )
        
        return jsonify({
            "success": True,
            "deployment_url": deployment_result['deployment_url'],
            "github_repo": deployment_result['github_repo'],
            "status": "deployed"
        })
        
    except Exception as e:
        logger.exception(f"Error deploying portfolio: {str(e)}")
        return jsonify({"error": f"Failed to deploy portfolio: {str(e)}"}), 500

@portfolio_bp.route('/list', methods=['GET'])
@jwt_required_wrapper
def list_portfolios():
    """
    List all portfolios for a user
    """
    try:
        user_id = g.user_id
        
        # Get portfolios from the database
        portfolios = list_user_portfolios(user_id)
        
        return jsonify({
            "success": True,
            "portfolios": portfolios
        })
        
    except Exception as e:
        logger.exception(f"Error listing portfolios: {str(e)}")
        return jsonify({"error": "Failed to list portfolios"}), 500

@portfolio_bp.route('/<portfolio_id>', methods=['GET'])
@jwt_required_wrapper
def get_portfolio_by_id(portfolio_id):
    """
    Get a specific portfolio by ID
    """
    try:
        user_id = g.user_id
        
        # Validate the portfolio_id is a valid ObjectId
        try:
            portfolio_obj_id = ObjectId(portfolio_id)
        except Exception as e:
            logger.error(f"Invalid portfolio ID format: {portfolio_id}")
            return jsonify({"error": f"Invalid portfolio ID format: {str(e)}"}), 400
        
        # Get the portfolio from the database
        portfolio = get_portfolio(user_id, portfolio_obj_id)
        if not portfolio:
            return jsonify({"error": "Portfolio not found"}), 404
        
        # Check if the portfolio has components
        if not portfolio.get('components'):
            logger.warning(f"Portfolio {portfolio_id} has no components")
            return jsonify({"error": "Portfolio has no components"}), 500
            
        component_count = len(portfolio.get('components', {}))
        logger.info(f"Returning portfolio {portfolio_id} with {component_count} components")
        
        return jsonify({
            "success": True,
            "portfolio": portfolio
        })
        
    except Exception as e:
        logger.exception(f"Error getting portfolio: {str(e)}")
        return jsonify({"error": "Failed to get portfolio"}), 500


@portfolio_bp.route('/deployment-status/<deployment_id>', methods=['GET'])
@jwt_required_wrapper
def get_deployment_status(deployment_id):
    """
    Check the status of a deployment
    """
    try:
        from mongodb.database import db
        
        deployment = db.deployment_statuses.find_one({"_id": ObjectId(deployment_id)})
        if not deployment:
            return jsonify({"error": "Deployment not found"}), 404
        
        return jsonify({
            "status": deployment.get("status"),
            "progress": deployment.get("progress"),
            "url": deployment.get("url"),
            "github_repo": deployment.get("github_repo"),
            "error": deployment.get("error")
        })
        
    except Exception as e:
        logger.exception(f"Error checking deployment status: {str(e)}")
        return jsonify({"error": "Failed to check deployment status"}), 500  



# Database helper functions
def save_portfolio(user_id, components, preferences, resume_text=None):
    """Save portfolio to database"""
    from mongodb.database import db
    
    portfolio_doc = {
        "user_id": ObjectId(user_id),
        "components": components,
        "preferences": preferences,
        "resume_text": resume_text,  
        "created_at": time.time(),
        "status": "generated",
        "deployment": {
            "deployed": False,
            "url": None,
            "github_repo": None
        }
    }
    
    result = db.portfolios.insert_one(portfolio_doc)
    return result.inserted_id

def get_portfolio(user_id, portfolio_id):
    """Get portfolio from database"""
    from mongodb.database import db
    
    try:
        portfolio = db.portfolios.find_one({
            "user_id": ObjectId(user_id),
            "_id": ObjectId(portfolio_id)
        })
        
        if portfolio:
            portfolio["_id"] = str(portfolio["_id"])
            portfolio["user_id"] = str(portfolio["user_id"])
        
        return portfolio
    
    except Exception as e:
        logger.error(f"Error getting portfolio: {str(e)}")
        return None

def update_portfolio_component(user_id, portfolio_id, component_path, code):
    """Update a specific component in the portfolio"""
    from mongodb.database import db
    
    try:
        db.portfolios.update_one(
            {
                "user_id": ObjectId(user_id),
                "_id": ObjectId(portfolio_id)
            },
            {
                "$set": {
                    f"components.{component_path}": code,
                    "updated_at": time.time()
                }
            }
        )
        
        return True
    
    except Exception as e:
        logger.error(f"Error updating portfolio component: {str(e)}")
        return False

def update_portfolio_deployment(user_id, portfolio_id, deployment_url, github_repo=None):
    """Update portfolio deployment information"""
    from mongodb.database import db
    
    try:
        db.portfolios.update_one(
            {
                "user_id": ObjectId(user_id),
                "_id": ObjectId(portfolio_id)
            },
            {
                "$set": {
                    "deployment.deployed": True,
                    "deployment.url": deployment_url,
                    "deployment.github_repo": github_repo,
                    "deployment.deployed_at": time.time(),
                    "status": "deployed"
                }
            }
        )
        
        return True
    
    except Exception as e:
        logger.error(f"Error updating portfolio deployment: {str(e)}")
        return False

def list_user_portfolios(user_id):
    """List all portfolios for a user"""
    from mongodb.database import db
    
    try:
        portfolios = list(db.portfolios.find(
            {"user_id": ObjectId(user_id)},
            {
                "_id": 1,
                "status": 1,
                "created_at": 1,
                "deployment.deployed": 1,
                "deployment.url": 1,
                "preferences": 1
            }
        ))
        
        # Convert ObjectId to string
        for portfolio in portfolios:
            portfolio["_id"] = str(portfolio["_id"])
            portfolio["user_id"] = str(user_id)
        
        return portfolios
    
    except Exception as e:
        logger.error(f"Error listing portfolios: {str(e)}")
        return []
        

