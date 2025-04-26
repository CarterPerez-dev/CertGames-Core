# helpers/ai_guardrails.py
import logging
import json
from datetime import datetime, timedelta
from bson.objectid import ObjectId
from mongodb.database import db, mainusers_collection
from flask import g, request

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


AI_OPERATION_LIMITS = {
    'analogy': {'max_chars': 1000, 'max_tokens': 2000, 'max_calls': 40, 'period': 3600},
    'scenario': {'max_chars': 1000, 'max_tokens': 3000, 'max_calls': 20, 'period': 3600},
    'grc': {'max_chars': 1000, 'max_tokens': 1500, 'max_calls': 35, 'period': 3600},
    'xploit': {'max_chars': 1000, 'max_tokens': 4000, 'max_calls': 30, 'period': 3600}
}


DEFAULT_LIMITS = {'max_chars': 100, 'max_tokens': 2000, 'max_calls': 35, 'period': 3600}

def limit_input_length(text, operation_type=None, custom_max=None):
    """
    Limit input text to a reasonable number of characters
    
    Args:
        text (str): The text to limit
        operation_type (str): Type of operation (analogy, scenario, etc.)
        custom_max (int): Optional custom maximum length
        
    Returns:
        str: The limited text
    """
    if text is None:
        return None
        
    # Convert to string if not already
    if not isinstance(text, str):
        text = str(text)
        
    # Get max characters for this operation type
    max_chars = custom_max
    if max_chars is None:
        limits = AI_OPERATION_LIMITS.get(operation_type, DEFAULT_LIMITS)
        max_chars = limits['max_chars']
    
    # Truncate if needed
    if len(text) > max_chars:
        logger.warning(f"Input text truncated from {len(text)} to {max_chars} characters")
        return text[:max_chars]
    
    return text

def estimate_tokens(text):
    """
    Roughly estimate number of tokens in text (4 chars ≈ 1 token)
    
    Args:
        text (str): The text to estimate tokens for
        
    Returns:
        int: Estimated number of tokens
    """
    if not text:
        return 0
    return len(text) // 4

def check_token_limit(text, operation_type=None, custom_max=None):
    """
    Check if text exceeds token limit
    
    Args:
        text (str): The text to check
        operation_type (str): Type of operation (analogy, scenario, etc.)
        custom_max (int): Optional custom maximum tokens
        
    Returns:
        tuple: (is_within_limit, estimated_tokens)
    """
    # Get max tokens for this operation type
    max_tokens = custom_max
    if max_tokens is None:
        limits = AI_OPERATION_LIMITS.get(operation_type, DEFAULT_LIMITS)
        max_tokens = limits['max_tokens']
    
    estimated_tokens = estimate_tokens(text)
    return estimated_tokens <= max_tokens, estimated_tokens


def log_ai_request(user_id, operation_type, estimated_tokens, model="gpt-4o"):
    """
    Log AI requests for monitoring and analysis
    
    Args:
        user_id (str): The user's ID
        operation_type (str): Type of operation
        estimated_tokens (int): Estimated number of tokens
        model (str): The AI model used
    """
    try:
        # Get IP address and other details for logging
        ip_address = request.remote_addr or "unknown"
        user_agent = request.headers.get('User-Agent', '')[:200]
        
        # Create log entry
        log_entry = {
            "userId": ObjectId(user_id) if user_id else None,
            "ipAddress": ip_address,
            "userAgent": user_agent,
            "operationType": operation_type,
            "estimatedTokens": estimated_tokens,
            "model": model,
            "timestamp": datetime.utcnow(),
            "expiresAt": datetime.utcnow() + timedelta(days=30)  # TTL for auto-cleanup
        }
        
        # Insert log entry
        db.ai_usage_logs.insert_one(log_entry)
        
    except Exception as e:
        logger.error(f"Error logging AI request: {str(e)}")

def apply_ai_guardrails(prompt, operation_type, user_id=None, model="gpt-4o"):
    """
    Apply all guardrails to an AI operation
    
    Args:
        prompt (str): The prompt text
        operation_type (str): Type of operation
        user_id (str): The user's ID
        model (str): The AI model to use
        
    Returns:
        tuple: (proceed, prompt, message)
            - proceed (bool): Whether to proceed with the operation
            - prompt (str): The potentially modified prompt
            - message (str): Error message if proceed is False
    """
 

    prompt = limit_input_length(prompt, operation_type)
    

    is_within_limit, estimated_tokens = check_token_limit(prompt, operation_type)
    if not is_within_limit:
        return False, None, f"Input exceeds maximum token limit ({estimated_tokens} tokens). Please use shorter descriptions."
    

    log_ai_request(user_id, operation_type, estimated_tokens, model)
    
    # All checks passed
    return True, prompt, ""

def get_streaming_error_generator(error_message):
    """
    Create a generator that yields an error message (for streaming responses)
    
    Args:
        error_message (str): The error message
        
    Returns:
        generator: A generator that yields the error message
    """
    def error_generator():
        yield error_message
    return error_generator



