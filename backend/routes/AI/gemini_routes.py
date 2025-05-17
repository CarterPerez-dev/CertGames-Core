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
from models.test import get_user_by_id, get_github_token_for_user

from middleware.subscription_check import subscription_required
from helpers.gemini_helper import gemini_helper
from models.test import get_user_by_id
from helpers.ai_guard import apply_ai_guardrails
from helpers.rate_limiter import rate_limit
from helpers.jwt_auth import jwt_required_wrapper
from mongodb.database import db

portfolio_bp = Blueprint('portfolio', __name__)
logger = logging.getLogger(__name__)

generation_tasks = {}

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
                logger.warning(f"User {user_id_from_g} opted for OAuth token, but none found in DB.")
                # If github_token_from_input is also empty, then it's a definite error.
                if not github_token_from_input:
                    return jsonify({"error": "You opted to use a linked GitHub account, but no token was found. Please re-link your GitHub account or provide a token manually."}), 400
                else:
                    # Fallback to input if OAuth token not found but input is present.
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
        
        # Store task info in MongoDB instead of in-memory dictionary
        db.deployment_tasks.insert_one({
            "task_id": task_id,
            "status": "pending",
            "user_id": user_id_from_g,
            "portfolio_id": portfolio_id_str_for_task,
            "error": None,
            "result": None,
            "started_at": time.time(),
            "finished_at": None
        })
        
        # The background task runner definition remains the same
        def deployment_background_task_runner(app_context, local_task_id, p_user_id, p_id, gh_token, vc_token, port_components):
            # ... (same as before, uses gh_token passed to it)
            with app_context:
                try:
                    logger.info(f"Background task {local_task_id} using GitHub token: {'****' + gh_token[-4:] if gh_token else 'None'}")
                    from utils.deployment_service import deployment_service                     
                    deployment_result_bg = deployment_service.deploy_to_vercel(
                        p_user_id, p_id, gh_token, vc_token, port_components
                    )
                    update_portfolio_deployment(
                        p_user_id, p_id, deployment_result_bg['deployment_url'],
                        deployment_result_bg['github_repo']
                    )
                    
                    # Update task status in MongoDB
                    db.deployment_tasks.update_one(
                        {"task_id": local_task_id},
                        {"$set": {
                            "status": "completed",
                            "result": deployment_result_bg,
                            "finished_at": time.time()
                        }}
                    )
                except Exception as e_deploy_bg:
                    logger.exception(f"BG task {local_task_id} FAILED")
                    
                    # Update error status in MongoDB
                    db.deployment_tasks.update_one(
                        {"task_id": local_task_id},
                        {"$set": {
                            "status": "failed",
                            "error": str(e_deploy_bg),
                            "finished_at": time.time()
                        }}
                    )

        # Pass 'github_token_to_use' to the thread
        thread = threading.Thread(
            target=deployment_background_task_runner,
            args=(
                current_app.app_context(), 
                task_id,
                user_id_from_g,
                portfolio_id_str_for_task, 
                github_token_to_use,
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
            "status_url": f"/portfolio/deploy/status/{task_id}"
        }), 202
        
    except Exception as e:
        current_user_for_log = str(g.user_id) if hasattr(g, 'user_id') and g.user_id else "UNKNOWN_USER"
        logger.exception(f"Error in /deploy route before starting task for user {current_user_for_log}")
        return jsonify({"error": f"Failed to initiate portfolio deployment: {str(e)}"}), 500

@portfolio_bp.route('/deploy/status/<task_id>', methods=['GET'])
@jwt_required_wrapper
def get_deployment_status_route(task_id):
    # Get status from database instead of memory
    task_info = db.deployment_tasks.find_one({"task_id": task_id})
    
    if not task_info:
        logger.warning(f"Deployment task not found in database: {task_id}")
        # Check if we want to make this failsafe by using in-memory dictionary as fallback
        # (can help during the transition to the new method)
        return jsonify({"error": "Deployment task not found. It may have expired or not exist."}), 404

    if str(g.user_id) != str(task_info.get("user_id")):
        logger.warning(f"User {g.user_id} attempting to access deployment task {task_id} of user {task_info.get('user_id')}")
        return jsonify({"error": "Access forbidden to this deployment task status"}), 403

    # Convert ObjectId to string for JSON serialization
    if '_id' in task_info:
        task_info['_id'] = str(task_info['_id'])

    return jsonify({
        "task_id": task_id,
        "status": task_info["status"],
        "result": task_info.get("result"),
        "error": task_info.get("error"),
        "started_at": task_info.get("started_at"),
        "finished_at": task_info.get("finished_at"),
        "portfolio_id": task_info.get("portfolio_id"),
        "progress": _calculate_deployment_progress(task_info)
    })

def _calculate_deployment_progress(task_info):
    """Calculate an approximate progress percentage based on time elapsed and status"""
    if task_info.get("status") == "completed":
        return 100
    elif task_info.get("status") == "failed":
        return 0
    
    # For in-progress deployments, estimate based on time (typical deployment takes ~2 minutes)
    started_at = task_info.get("started_at", 0)
    elapsed_seconds = time.time() - started_at
    
    # Rough estimate: 0-30s: 0-30%, 30-60s: 30-60%, 60-90s: 60-90%, >90s: 90%
    if elapsed_seconds < 30:
        return int(elapsed_seconds)
    elif elapsed_seconds < 60:
        return 30 + int((elapsed_seconds - 30) * 1)
    elif elapsed_seconds < 90:
        return 60 + int((elapsed_seconds - 60) * 1)
    else:
        return 90  # Cap at 90% until complete
