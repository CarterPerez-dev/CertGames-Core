from flask import Blueprint, request, jsonify
from helpers.xploitcraft_helper import Xploits
import logging

# Configure logger
logger = logging.getLogger(__name__)

xploit = Xploits()
xploit_bp = Blueprint('xploit_bp', __name__)

@xploit_bp.route('/generate_payload', methods=['POST'])
def generate_payload_endpoint():
    data = request.get_json()
    logger.debug(f"Received data: {data}")

    # Allow for either vulnerability or evasion_technique or both.
    # If neither is provided, return error.
    if not data or (not data.get('vulnerability') and not data.get('evasion_technique')):
        logger.error("Invalid request payload - need at least one of vulnerability or evasion_technique")
        return jsonify({'error': 'Please provide at least one of vulnerability or evasion_technique'}), 400

    vulnerability = data.get('vulnerability', "")
    evasion_technique = data.get('evasion_technique', "")

    try:
        payload = xploit.generate_exploit_payload(vulnerability, evasion_technique)
        logger.debug(f"Generated payload: {payload}")
        return jsonify({'payload': payload})
    except Exception as e:
        logger.error(f"Error while generating payload: {str(e)}")
        return jsonify({'error': 'Failed to generate payload'}), 500

