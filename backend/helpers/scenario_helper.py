import logging
import json  
from flask import Blueprint, request, Response, jsonify
from helpers.scenario_helper import (
    generate_scenario,
    generate_interactive_questions,
    break_down_scenario
)

scenario_bp = Blueprint('scenario_bp', __name__)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

@scenario_bp.route('/stream_scenario', methods=['POST'])
def stream_scenario_endpoint():
    """
    Streams scenario text in real time (token-by-token).
    Expects JSON with { industry, attack_type, skill_level, threat_intensity }
    Returns a text/plain streaming response.
    """
    data = request.get_json() or {}
    required_fields = ["industry", "attack_type", "skill_level", "threat_intensity"]
    missing = [f for f in required_fields if f not in data]
    if missing:
        logger.error(f"Missing required fields: {missing}")
        return jsonify({"error": f"Missing required fields: {missing}"}), 400

    industry = data["industry"]
    attack_type = data["attack_type"]
    skill_level = data["skill_level"]
    threat_intensity = data["threat_intensity"]

    try:
        threat_intensity = int(threat_intensity)
    except ValueError:
        logger.error("Invalid threat_intensity value; must be an integer.")
        return jsonify({"error": "threat_intensity must be an integer"}), 400

    def generate_chunks():
        scenario_generator = generate_scenario(industry, attack_type, skill_level, threat_intensity)
        # Log the start of streaming
        logger.info(f"Starting scenario stream for {industry}, {attack_type}")
        for chunk in scenario_generator:
            # Log chunk size for debugging
            if isinstance(chunk, str) and len(chunk) > 0:
                logger.debug(f"Streaming chunk of size: {len(chunk)}")
            yield chunk

    # Create the streaming response with all necessary headers
    response = Response(generate_chunks(), mimetype='text/plain')
    
    # Essential headers for preventing buffering
    response.headers['X-Accel-Buffering'] = 'no'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['Content-Type'] = 'text/plain; charset=utf-8'
    
    # Enable chunked transfer encoding
    response.headers['Transfer-Encoding'] = 'chunked'
    
    # Keep connection alive for streaming
    response.headers['Connection'] = 'keep-alive'
    
    logger.info("Returning streaming response with headers set")
    return response


@scenario_bp.route('/stream_questions', methods=['POST'])
def stream_questions_endpoint():
    """
    Streams the interactive questions (in raw JSON form) in real time, token-by-token.
    Expects JSON with { "scenario_text": "..." }
    The front end can accumulate the text and parse once done.
    """
    data = request.get_json() or {}
    scenario_text = data.get("scenario_text", "")
    if not scenario_text:
        logger.error("Missing scenario_text in the request.")
        return jsonify({"error": "Missing scenario_text"}), 400

    logger.debug(f"Received scenario_text: {scenario_text[:100]}...")  

    def generate_json_chunks():
        logger.info("Starting to generate questions")
        questions = generate_interactive_questions(scenario_text)
        if isinstance(questions, list):
            logger.debug("Questions are a list. Serializing to JSON.")
            json_data = json.dumps(questions)
            logger.debug(f"Sending JSON data of size: {len(json_data)}")
            yield json_data
        elif callable(questions):
            logger.debug("Questions are being streamed.")
            for chunk in questions():
                if chunk:
                    logger.debug(f"Streaming question chunk of size: {len(chunk)}")
                yield chunk
        else:
            logger.error("Unexpected type for questions.")
            yield json.dumps([{"error": "Failed to generate questions."}])

    # Create the streaming response with all necessary headers
    response = Response(generate_json_chunks(), mimetype='application/json')
    
    # Essential headers for preventing buffering
    response.headers['X-Accel-Buffering'] = 'no'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    # Enable chunked transfer encoding
    response.headers['Transfer-Encoding'] = 'chunked'
    
    # Keep connection alive for streaming
    response.headers['Connection'] = 'keep-alive'
    
    logger.info("Returning streaming questions response with headers set")
    return response
