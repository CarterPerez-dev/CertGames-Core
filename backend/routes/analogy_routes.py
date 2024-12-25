# analogy_routes.py

from flask import Blueprint, request, jsonify
import logging
# Import the Celery tasks
from helpers.async_tasks import (
    generate_single_analogy_task,
    generate_comparison_analogy_task,
    generate_triple_comparison_analogy_task
)

analogy_bp = Blueprint('analogy_bp', __name__)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

@analogy_bp.route('/generate_analogy', methods=['POST'])
def generate_analogy():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request must contain data"}), 400

    analogy_type = data.get("analogy_type")
    category = data.get("category")
    concept1 = data.get("concept1")
    concept2 = data.get("concept2")
    concept3 = data.get("concept3")

    try:
        if analogy_type == "single" and concept1:
            async_result = generate_single_analogy_task.delay(concept1, category)
            analogy_text = async_result.get(timeout=120)
            return jsonify({"analogy": analogy_text}), 200

        elif analogy_type == "comparison" and concept1 and concept2:
            async_result = generate_comparison_analogy_task.delay(concept1, concept2, category)
            analogy_text = async_result.get(timeout=120)
            return jsonify({"analogy": analogy_text}), 200

        elif analogy_type == "triple" and concept1 and concept2 and concept3:
            async_result = generate_triple_comparison_analogy_task.delay(concept1, concept2, concept3, category)
            analogy_text = async_result.get(timeout=180)
            return jsonify({"analogy": analogy_text}), 200

        else:
            logger.error("Invalid parameters provided")
            return jsonify({"error": "Invalid parameters"}), 400

    except Exception as e:
        logger.error(f"Error generating analogy: {e}")
        return jsonify({"error": "An internal error occurred while generating the analogy."}), 500

