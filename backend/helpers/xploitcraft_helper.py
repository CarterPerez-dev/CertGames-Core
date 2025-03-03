import logging
from flask import Blueprint, request, Response, jsonify
from helpers.xploits import Xploits

xploit_bp = Blueprint('xploit_bp', __name__)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Create a single instance of Xploits to be used across requests
xploits = Xploits()

@xploit_bp.route('/stream_payload', methods=['POST'])
def stream_payload_endpoint():
    """
    Streams exploit payload in real time (token-by-token).
    Expects JSON with { vulnerability, evasion_technique }
    Returns a text/plain streaming response.
    """
    data = request.get_json() or {}
    vulnerability = data.get("vulnerability", "")
    evasion_technique = data.get("evasion_technique", "")

    if not vulnerability and not evasion_technique:
        logger.error("Missing required fields: either vulnerability or evasion_technique must be provided")
        return jsonify({"error": "At least one of vulnerability or evasion_technique must be provided"}), 400

    try:
        def generate_chunks():
            logger.info(f"Starting payload stream for vulnerability: '{vulnerability}', evasion: '{evasion_technique}'")
            payload_generator = xploits.generate_exploit_payload(
                vulnerability=vulnerability,
                evasion_technique=evasion_technique,
                stream=True
            )
            
            # Stream each chunk as it's generated
            for chunk in payload_generator:
                if isinstance(chunk, str) and len(chunk) > 0:
                    logger.debug(f"Streaming payload chunk of size: {len(chunk)}")
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
        
        logger.info("Returning streaming payload response with headers set")
        return response

    except Exception as e:
        logger.error(f"Error generating payload: {str(e)}")
        return jsonify({"error": str(e)}), 500

@xploit_bp.route('/payload', methods=['POST'])
def generate_payload_endpoint():
    """
    Generates a complete exploit payload (non-streaming).
    Expects JSON with { vulnerability, evasion_technique }
    Returns a JSON response with the full payload.
    """
    data = request.get_json() or {}
    vulnerability = data.get("vulnerability", "")
    evasion_technique = data.get("evasion_technique", "")

    if not vulnerability and not evasion_technique:
        logger.error("Missing required fields: either vulnerability or evasion_technique must be provided")
        return jsonify({"error": "At least one of vulnerability or evasion_technique must be provided"}), 400

    try:
        logger.info(f"Generating non-streaming payload for vulnerability: '{vulnerability}', evasion: '{evasion_technique}'")
        payload = xploits.generate_exploit_payload(
            vulnerability=vulnerability,
            evasion_technique=evasion_technique,
            stream=False
        )
        
        logger.info(f"Successfully generated payload of length: {len(payload)}")
        return jsonify({"payload": payload})
    
    except Exception as e:
        logger.error(f"Error generating payload: {str(e)}")
        return jsonify({"error": str(e)}), 500
