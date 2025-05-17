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
from utils.deployment_service import deployment_service
from models.test import get_user_by_id, get_github_token_for_user # Add it here

from middleware.subscription_check import subscription_required
from helpers.gemini_helper import gemini_helper
from models.test import get_user_by_id
from helpers.ai_guard import apply_ai_guardrails
from helpers.rate_limiter import rate_limit
from helpers.jwt_auth import jwt_required_wrapper

deployment_tasks = {}
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
def deploy_portfolio():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request format"}), 400
        
        user_id_from_g = str(g.user_id)
        portfolio_id_req = data.get('portfolio_id')
        vercel_token = data.get('vercel_token')
        
        # This is the token from the input box
        github_token_from_input = data.get('github_token') 
        
        # use_oauth indicates if the user *wants* to try using a stored OAuth token.
        # If the frontend doesn't send use_oauth, assume they are using the input box.
        use_oauth_preference = data.get('use_oauth', False) 

        github_token_to_use = None

        if use_oauth_preference:
            # User wants to use their stored OAuth token. Try to fetch it.
            logger.info(f"User {user_id_from_g} opted to use stored OAuth token.")
            stored_oauth_token = get_github_token_for_user(user_id_from_g)
            if stored_oauth_token:
                github_token_to_use = stored_oauth_token
                logger.info(f"Successfully retrieved stored OAuth token for user {user_id_from_g}.")
            else:
                # Stored token not found, but user preferred it.
                # Option 1: Error out, tell them to re-auth or use manual input.
                logger.warning(f"User {user_id_from_g} opted for OAuth token, but none found in DB.")
                # If github_token_from_input is also empty, then it's a definite error.
                if not github_token_from_input:
                    return jsonify({"error": "You opted to use a linked GitHub account, but no token was found. Please re-link your GitHub account or provide a token manually."}), 400
                else:
                    # Option 2: Fallback to input if OAuth token not found but input is present.
                    logger.info(f"OAuth token not found for {user_id_from_g}, but a token was provided in the input. Using input token.")
                    github_token_to_use = github_token_from_input
        else:
            # User did not opt for OAuth (or flag was false/missing), so rely on the input box.
            logger.info(f"User {user_id_from_g} did not opt for OAuth token, or flag not set. Checking input token.")
            if github_token_from_input:
                github_token_to_use = github_token_from_input
                logger.info(f"Using GitHub token provided in input for user {user_id_from_g}.")
            else:
                # No OAuth preference, and no token in input. This is an error.
                logger.error(f"GitHub token not provided in input, and OAuth not selected by user {user_id_from_g}.")
                return jsonify({"error": "GitHub token is required. Please provide it in the input field or link your GitHub account."}), 400


        if not all([portfolio_id_req, github_token_to_use, vercel_token]):
            missing = []
            if not portfolio_id_req: missing.append("portfolio_id")
            if not github_token_to_use: missing.append("github_token (either from OAuth or input)")
            if not vercel_token: missing.append("vercel_token")
            logger.error(f"Deployment pre-check failed for user {user_id_from_g}. Missing: {', '.join(missing)}")
            return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400


        

        portfolio = get_portfolio(user_id_from_g, portfolio_id_req)


        portfolio_components = portfolio.get('components', {})
        if not portfolio_components:
             logger.error(f"Portfolio {portfolio_id_req} for user {user_id_from_g} has no components to deploy.")
             return jsonify({"error": "Portfolio has no content (components) to deploy."}), 400

        portfolio_id_str_for_task = str(portfolio_id_req)
        task_id = f"deploy_{user_id_from_g}_{portfolio_id_str_for_task}_{int(time.time())}"
        deployment_tasks[task_id] = { # Ensure deployment_tasks is defined globally in this module
            "status": "pending", "user_id": user_id_from_g, "portfolio_id": portfolio_id_str_for_task,
            "error": None, "result": None, "started_at": time.time(), "finished_at": None
        }
        
        # The background task runner definition remains the same
        def deployment_background_task_runner(app_context, local_task_id, p_user_id, p_id, gh_token, vc_token, port_components):
            # ... (same as before, uses gh_token passed to it)
            with app_context:
                try:
                    logger.info(f"Background task {local_task_id} using GitHub token: {'****' + gh_token[-4:] if gh_token else 'None'}") # Log partial token
                    from utils.deployment_service import deployment_service                     
                    deployment_result_bg = deployment_service.deploy_to_vercel(
                        p_user_id, p_id, gh_token, vc_token, port_components
                    )
                    update_portfolio_deployment( 
                        p_user_id, p_id, deployment_result_bg['deployment_url'],
                        deployment_result_bg['github_repo']
                    )
                    deployment_tasks[local_task_id]["status"] = "completed"
                    deployment_tasks[local_task_id]["result"] = deployment_result_bg
                    deployment_tasks[local_task_id]["finished_at"] = time.time()
                except Exception as e_deploy_bg:
                    logger.exception(f"BG task {local_task_id} FAILED")
                    deployment_tasks[local_task_id]["status"] = "failed"
                    deployment_tasks[local_task_id]["error"] = str(e_deploy_bg)
                    deployment_tasks[local_task_id]["finished_at"] = time.time()

        # Pass 'github_token_to_use' to the thread
        thread = threading.Thread(
            target=deployment_background_task_runner,
            args=(
                current_app.app_context(), 
                task_id,
                user_id_from_g,
                portfolio_id_str_for_task, 
                github_token_to_use, # <<< Pass the resolved token
                vercel_token, 
                portfolio_components
            )
        )
        thread.daemon = True 
        thread.start()
        logger.info(f"Deployment task {task_id} submitted for user {user_id_from_g}, portfolio {portfolio_id_str_for_task}")

        return jsonify({
            "success": True,
            "message": "Portfolio deployment has been initiated. Please check status using the task ID.",
            "task_id": task_id,
            "status_url": f"/portfolio/deploy/status/{task_id}" # Ensure URL prefix matches blueprint
        }), 202
        
    except Exception as e:
        current_user_for_log = str(g.user_id) if hasattr(g, 'user_id') and g.user_id else "UNKNOWN_USER"
        logger.exception(f"Error in /deploy route before starting task for user {current_user_for_log}")
        return jsonify({"error": f"Failed to initiate portfolio deployment: {str(e)}"}), 500

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
def get_portfolio(user_id, portfolio_id):
    """Get portfolio from database and format it for the frontend"""
    from mongodb.database import db
    
    try:
        portfolio = db.portfolios.find_one({
            "user_id": ObjectId(user_id),
            "_id": ObjectId(portfolio_id)
        })
        
        if portfolio:
            portfolio["_id"] = str(portfolio["_id"])
            portfolio["user_id"] = str(portfolio["user_id"])
            
            # If the portfolio uses the new structure, convert it back to the format expected by frontend
            if "components_array" in portfolio and isinstance(portfolio["components_array"], list):
                # Convert array back to dict for the frontend
                components_dict = {}
                for component in portfolio["components_array"]:
                    if "path" in component and "content" in component:
                        components_dict[component["path"]] = component["content"]
                
                portfolio["components"] = components_dict
            
            # If there's no components dict but there is components_array, create a components dict
            elif "components" not in portfolio and "components_array" in portfolio:
                portfolio["components"] = {}
                for component in portfolio["components_array"]:
                    if "path" in component and "content" in component:
                        portfolio["components"][component["path"]] = component["content"]
        
        return portfolio
    
    except Exception as e:
        logger.error(f"Error getting portfolio: {str(e)}")
        return None


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

@portfolio_bp.route('/deploy/status/<task_id>', methods=['GET'])
@jwt_required_wrapper # Or appropriate authentication for this endpoint
def get_deployment_status_route(task_id):
    # Ensure deployment_tasks is accessible (e.g., global in this module)
    task_info = deployment_tasks.get(task_id)
    
    if not task_info:
        return jsonify({"error": "Deployment task not found"}), 404


    if str(g.user_id) != str(task_info.get("user_id")):
        logger.warning(f"User {g.user_id} attempting to access deployment task {task_id} of user {task_info.get('user_id')}")
        return jsonify({"error": "Access forbidden to this deployment task status"}), 403

    return jsonify({
        "task_id": task_id,
        "status": task_info["status"],
        "result": task_info.get("result"), # Will contain URLs on "completed"
        "error": task_info.get("error"),   # Will contain error message on "failed"
        "started_at": task_info.get("started_at"),
        "finished_at": task_info.get("finished_at"),
        "portfolio_id": task_info.get("portfolio_id")
    })




@portfolio_bp.route('/create-file', methods=['POST'])
@jwt_required_wrapper
def create_portfolio_file():
    try:
        data = request.get_json()
        user_id = g.user_id
        portfolio_id = data.get('portfolio_id')
        file_path = data.get('file_path', '').strip() # Add strip
        content = data.get('content')
        
        if not all([portfolio_id, file_path, content is not None]): # check content is not None
            logger.error(f"Create file missing fields: portfolio_id={portfolio_id}, file_path='{file_path}', content_present={content is not None}")
            return jsonify({"error": "Missing required fields (portfolio_id, file_path, content)"}), 400
        
        # Get portfolio
        portfolio = get_portfolio(user_id, portfolio_id) # Ensure get_portfolio handles string IDs
        if not portfolio:
            return jsonify({"error": "Portfolio not found"}), 404
        
        # Check if file already exists - use exact file_path as provided
        components = portfolio.get('components', {})
        if file_path in components: # This check is against keys that might already be extensionless if error persisted
            logger.warning(f"File '{file_path}' already exists in components for portfolio {portfolio_id}.")
            # Depending on desired behavior, you might allow overwrite or return error
            # For now, let's assume an update is fine, or it's a new file.
            # return jsonify({"error": "File already exists"}), 400 

        logger.info(f"Calling update_portfolio_component for CREATE: User: {user_id}, Portfolio: {portfolio_id}, Path: '{file_path}'")
        result = update_portfolio_component(user_id, portfolio_id, file_path, content)
        
        if result:
            return jsonify({
                "success": True, 
                "message": "File created/updated successfully",
                "file_path": file_path # Return the exact path used
            })
        else:
            return jsonify({"error": "Failed to create/update file"}), 500
    
    except Exception as e:
        logger.exception(f"Error creating file: {str(e)}")
        return jsonify({"error": f"Error creating file: {str(e)}"}), 500

# In your /update-file route:
@portfolio_bp.route('/update-file', methods=['POST'])
@jwt_required_wrapper
def update_portfolio_file():
    try:
        data = request.get_json()
        user_id = g.user_id
        portfolio_id = data.get('portfolio_id')
        file_path = data.get('file_path', '').strip() # Add strip
        content = data.get('content')
        
        if not all([portfolio_id, file_path, content is not None]): # check content is not None
            logger.error(f"Update file missing fields: portfolio_id={portfolio_id}, file_path='{file_path}', content_present={content is not None}")
            return jsonify({"error": "Missing required fields (portfolio_id, file_path, content)"}), 400
        

        
        logger.info(f"Calling update_portfolio_component for UPDATE: User: {user_id}, Portfolio: {portfolio_id}, Path: '{file_path}'")
        result = update_portfolio_component(user_id, portfolio_id, file_path, content)
        
        if result:
            return jsonify({
                "success": True, 
                "message": "File updated successfully",
                "file_path": file_path # Return the exact path used
            })
        else:
            return jsonify({"error": "Failed to update file"}), 500
    
    except Exception as e:
        logger.exception(f"Error updating file: {str(e)}")
        return jsonify({"error": f"Error updating file: {str(e)}"}), 500


@portfolio_bp.route('/delete-file', methods=['POST'])
@jwt_required_wrapper
def delete_portfolio_file():
    try:
        data = request.get_json()
        user_id = g.user_id
        portfolio_id = data.get('portfolio_id')
        file_path = data.get('file_path')
        
        if not all([portfolio_id, file_path]):
            return jsonify({"error": "Missing required fields"}), 400
        
        # Get portfolio
        portfolio = get_portfolio(user_id, portfolio_id)
        if not portfolio:
            return jsonify({"error": "Portfolio not found"}), 404
        
        # Check if file exists in components
        components = portfolio.get('components', {})
        if file_path not in components:
            return jsonify({"error": "File not found"}), 404
        
        # Delete file from the components_array
        from mongodb.database import db
        
        result = db.portfolios.update_one(
            {
                "user_id": ObjectId(user_id),
                "_id": ObjectId(portfolio_id)
            },
            {
                "$pull": {
                    "components_array": {"path": file_path}
                },
                "$set": {
                    "updated_at": time.time()
                }
            }
        )
        
        # Also remove from old components structure for compatibility
        result2 = db.portfolios.update_one(
            {
                "user_id": ObjectId(user_id),
                "_id": ObjectId(portfolio_id)
            },
            {
                "$unset": {
                    f"components.{file_path}": ""
                }
            }
        )
        
        if result.modified_count == 0 and result2.modified_count == 0:
            return jsonify({"error": "Failed to delete file"}), 500
        
        return jsonify({
            "success": True, 
            "message": "File deleted successfully"
        })
    
    except Exception as e:
        logger.exception(f"Error deleting file: {str(e)}")
        return jsonify({"error": f"Error deleting file: {str(e)}"}), 500
@portfolio_bp.route('/<portfolio_id>', methods=['DELETE'])
@jwt_required_wrapper
def delete_portfolio(portfolio_id):
    """
    Delete a portfolio and all its data
    """
    try:
        user_id = g.user_id
        
        # Verify the portfolio exists and belongs to the user
        from mongodb.database import db
        
        portfolio = db.portfolios.find_one({
            "user_id": ObjectId(user_id),
            "_id": ObjectId(portfolio_id)
        })
        
        if not portfolio:
            return jsonify({"error": "Portfolio not found"}), 404
            
        # Delete the portfolio
        result = db.portfolios.delete_one({
            "user_id": ObjectId(user_id),
            "_id": ObjectId(portfolio_id)
        })
        
        if result.deleted_count == 0:
            return jsonify({"error": "Failed to delete portfolio"}), 500
            
        logger.info(f"Portfolio {portfolio_id} deleted by user {user_id}")
        
        return jsonify({
            "success": True,
            "message": "Portfolio deleted successfully"
        })
        
    except Exception as e:
        logger.exception(f"Error deleting portfolio: {str(e)}")
        return jsonify({"error": f"Failed to delete portfolio: {str(e)}"}), 500
        
# Database helper functions
def save_portfolio(user_id, components, preferences, resume_text=None):
    """Save portfolio to database"""
    from mongodb.database import db
    
    # Convert the components dict to an array of objects
    components_array = []
    for path, content in components.items():
        components_array.append({
            "path": path,
            "content": content
        })
    
    portfolio_doc = {
        "user_id": ObjectId(user_id),
        "components_array": components_array,  # Store as array
        "components": components,  # Keep the old structure for backward compatibility
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


def update_portfolio_component(user_id, portfolio_id, component_path, code):
    """Update a specific component in the portfolio or create it if it doesn't exist."""
    from mongodb.database import db
    
    try:
        logger.info(f"Attempting to update/create component. User: {user_id}, Portfolio: {portfolio_id}, Path: '{component_path}', Code (first 50 chars): '{str(code)[:50]}...'")

        if not isinstance(component_path, str):
            logger.error(f"component_path is not a string: {type(component_path)}. Value: {component_path}")
            return False
            
        component_path = component_path.strip()
        if not component_path:
            logger.error("component_path is empty after stripping.")
            return False

        # Check if component already exists
        portfolio = db.portfolios.find_one({
            "user_id": ObjectId(user_id),
            "_id": ObjectId(portfolio_id),
            "components_array": {"$elemMatch": {"path": component_path}}
        })
        
        if portfolio:
            # Update existing component
            logger.info(f"Updating existing component '{component_path}'")
            update_result = db.portfolios.update_one(
                {
                    "user_id": ObjectId(user_id),
                    "_id": ObjectId(portfolio_id),
                    "components_array.path": component_path
                },
                {
                    "$set": {
                        "components_array.$.content": code,
                        "updated_at": time.time()
                    }
                }
            )
        else:
            # Add new component
            logger.info(f"Adding new component '{component_path}'")
            update_result = db.portfolios.update_one(
                {
                    "user_id": ObjectId(user_id),
                    "_id": ObjectId(portfolio_id)
                },
                {
                    "$push": {
                        "components_array": {
                            "path": component_path,
                            "content": code
                        }
                    },
                    "$set": {
                        "updated_at": time.time()
                    }
                }
            )
        
        if update_result.matched_count == 0:
            logger.error(f"No portfolio found with ID {portfolio_id} for user {user_id}. Cannot update component.")
            return False

        logger.info(f"Update result for component '{component_path}': Matched: {update_result.matched_count}, Modified: {update_result.modified_count}, UpsertedId: {update_result.upserted_id}")

        return True
    
    except Exception as e:
        logger.exception(f"Error in update_portfolio_component (Path: '{component_path}'): {str(e)}")
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
        
@portfolio_bp.route('/migrate-portfolios', methods=['POST'])
@jwt_required_wrapper
def migrate_portfolios():
    """Admin-only route to migrate existing portfolios to the new structure"""
    try:
        user_id = g.user_id
        
        # Check if admin
        from mongodb.database import db
        user = db.mainusers.find_one({"_id": ObjectId(user_id)})
        if not user or user.get('username') != 'admin':
            return jsonify({"error": "Unauthorized"}), 403
        
        # Find all portfolios that don't have components_array
        portfolios = db.portfolios.find({"components_array": {"$exists": False}})
        migrated_count = 0
        
        for portfolio in portfolios:
            components = portfolio.get('components', {})
            components_array = []
            
            for path, content in components.items():
                components_array.append({
                    "path": path,
                    "content": content
                })
            
            # Update the portfolio with the new array structure
            result = db.portfolios.update_one(
                {"_id": portfolio["_id"]},
                {
                    "$set": {
                        "components_array": components_array,
                        "migration_date": time.time()
                    }
                }
            )
            
            if result.modified_count > 0:
                migrated_count += 1
        
        return jsonify({
            "success": True,
            "message": f"Migration completed. {migrated_count} portfolios updated."
        })
        
    except Exception as e:
        logger.exception(f"Error migrating portfolios: {str(e)}")
        return jsonify({"error": f"Error migrating portfolios: {str(e)}"}), 500
