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

from helpers.gemini_helper import gemini_helper
from models.test import get_user_by_id
from helpers.ai_guard import apply_ai_guardrails
from helpers.rate_limiter import rate_limit
from helpers.jwt_auth import jwt_required_wrapper

portfolio_bp = Blueprint('portfolio', __name__)
logger = logging.getLogger(__name__)

@portfolio_bp.route('/generate-stream', methods=['POST'])
@jwt_required_wrapper
@rate_limit('general')
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
        
        # Initialize portfolio generation in a background thread
        def generate_portfolio_task():
            try:
                # Get user info
                user = get_user_by_id(user_id)
                if not user:
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
                            return
                        # Wait before retrying
                        time.sleep(2 ** attempt)  # Exponential backoff
                
                if portfolio_components:
                    # Save to database once generation succeeds
                    portfolio_id = save_portfolio(user_id, portfolio_components, preferences, resume_text)
                    logger.info(f"Portfolio {portfolio_id} successfully generated and saved")
                
            except Exception as e:
                logger.exception(f"Background task error: {str(e)}")

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



# In backend/routes/AI/gemini_routes.py
# Replace the route definition

@portfolio_bp.route('/status/generation', methods=['GET'])
@jwt_required_wrapper
def get_generation_status():
    """Check if the user has any recently generated portfolios"""
    user_id = g.user_id
    
    try:
        # Look for portfolios created in the last 10 minutes
        cutoff_time = time.time() - (10 * 60)  # 10 minutes ago
        
        from mongodb.database import db
        
        recent_portfolio = db.portfolios.find_one({
            "user_id": ObjectId(user_id),
            "created_at": {"$gt": cutoff_time}
        }, sort=[("created_at", -1)])
        
        if recent_portfolio:
            # Convert ObjectIds to strings
            portfolio_id = str(recent_portfolio["_id"])
            
            logger.info(f"Found recent portfolio for user {user_id}: {portfolio_id}")
            
            # Add more detailed logging for debugging
            logger.debug(f"Portfolio components count: {len(recent_portfolio.get('components', {}))}")
            
            return jsonify({
                "success": True,
                "status": "completed",
                "portfolio_id": portfolio_id,
                "components_count": len(recent_portfolio.get("components", {})),
                # Add creation timestamp to help with tracking
                "created_at": recent_portfolio.get("created_at")
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
            "message": "Failed to check generation status"
        }), 500

@portfolio_bp.route('/fix-error', methods=['POST'])
@jwt_required_wrapper
@rate_limit('general')
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
        
        # Fix the error
        fixed_code = gemini_helper.fix_portfolio_error(
            error_message, component_code, resume_text, preferences)
        
        # Update the portfolio in the database
        update_portfolio_component(user_id, portfolio_id, component_path, fixed_code)
        
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
def deploy_portfolio():
    """
    Deploy a portfolio to Vercel
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request format"}), 400
        
        user_id = g.user_id
        portfolio_id = data.get('portfolio_id')
        github_token = data.get('github_token')
        vercel_token = data.get('vercel_token')
        
        if not all([portfolio_id, github_token, vercel_token]):
            return jsonify({"error": "Missing required fields"}), 400
        
        # Get the portfolio from the database
        portfolio = get_portfolio(user_id, portfolio_id)
        if not portfolio:
            return jsonify({"error": "Portfolio not found"}), 404
        
        # In a real implementation, this would:
        # 1. Create a GitHub repository
        # 2. Commit the portfolio files
        # 3. Set up Vercel deployment
        # For now, we'll just simulate this
        
        deployment_url = f"https://{user_id}-portfolio.vercel.app"
        
        # Update the portfolio with deployment info
        update_portfolio_deployment(user_id, portfolio_id, deployment_url)
        
        return jsonify({
            "success": True,
            "deployment_url": deployment_url,
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
        
        return jsonify({
            "success": True,
            "portfolio": portfolio
        })
        
    except Exception as e:
        logger.exception(f"Error getting portfolio: {str(e)}")
        return jsonify({"error": "Failed to get portfolio"}), 500

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
