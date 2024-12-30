# scenario_routes.py

import logging
from flask import Blueprint, request, jsonify, session
from uuid import uuid4

from helpers.async_tasks import (
    generate_scenario_task,
    break_down_scenario_task,
    generate_interactive_questions_task
)
from scenario_logic.scenario_flow_manager import ScenarioFlowManager

scenario_bp = Blueprint('scenario_bp', __name__)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

flow_managers = {}

@scenario_bp.route('/generate_scenario', methods=['POST'])
def generate_scenario_endpoint():
    global flow_managers
    session_id = session.get('session_id')
    if not session_id:
        session_id = str(uuid4())
        session['session_id'] = session_id
        logger.info(f"Created new session ID: {session_id}")
    else:
        logger.info(f"Using existing session ID: {session_id}")

    data = request.get_json()
    if not data:
        logger.error("No data received in the request.")
        return jsonify({'error': 'Missing request data'}), 400

    required_fields = ['industry', 'attack_type', 'skill_level', 'threat_intensity']
    missing = [f for f in required_fields if f not in data]
    if missing:
        logger.error(f"Missing fields: {missing}")
        return jsonify({'error': f"Missing required fields: {missing}"}), 400

    industry = data['industry']
    attack_type = data['attack_type']
    skill_level = data['skill_level']
    threat_intensity = data['threat_intensity']

    try:
        threat_intensity = int(threat_intensity)
        if threat_intensity < 1 or threat_intensity > 100:
            raise ValueError
    except ValueError:
        return jsonify({'error': 'threat_intensity must be int 1-100'}), 400

    try:
        scenario_result = generate_scenario_task.delay(industry, attack_type, skill_level, threat_intensity)
        scenario_text = scenario_result.get(timeout=300)  

        breakdown_result = break_down_scenario_task.delay(scenario_text)
        scenario_breakdown = breakdown_result.get(timeout=120)

        questions_result = generate_interactive_questions_task.delay(scenario_text)
        interactive_questions = questions_result.get(timeout=120)

        flow_managers[session_id] = ScenarioFlowManager(scenario_breakdown)

        return jsonify({
            'scenario': scenario_text,
            'breakdown': scenario_breakdown,
            'interactive_questions': interactive_questions
        }), 200
    except Exception as e:
        logger.error(f"Error generating scenario: {e}")
        return jsonify({'error': 'An error occurred while generating the scenario.Please try again, in the process of fixing this'}), 500

