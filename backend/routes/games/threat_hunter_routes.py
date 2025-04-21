# backend/routes/games/threat_hunter_routes.py
from flask import Blueprint, request, jsonify, g
from bson.objectid import ObjectId
import time
from datetime import datetime
import random

from mongodb.database import db
from models.test import get_user_by_id, update_user_coins, update_user_xp
from utils.utils import check_and_unlock_achievements

# Initialize the blueprint
threat_hunter_bp = Blueprint('threat_hunter', __name__)

# Database collections
log_scenarios_collection = db.logScenarios
log_analysis_collection = db.logAnalysis

@threat_hunter_bp.route('/scenarios', methods=['GET'])
def get_log_scenarios():
    """
    Get all log analysis scenarios with metadata.
    Returns a list of scenario objects with IDs, titles, descriptions, etc.
    """
    start_db = time.time()
    # Get custom scenarios from the database
    db_scenarios = list(log_scenarios_collection.find({}, {
        '_id': 0,
        'logs.content': 0  # Exclude the actual log content for efficiency
    }))
    duration = time.time() - start_db
    if hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator += duration
    
    # Return the database scenarios (no fallback anymore)
    return jsonify(db_scenarios)

@threat_hunter_bp.route('/start-scenario', methods=['POST'])
def start_scenario():
    """
    Start a log analysis scenario and get the full scenario data including logs.
    """
    data = request.json
    scenario_id = data.get('scenarioId')
    user_id = data.get('userId')
    difficulty = data.get('difficulty', 'medium')
    
    if not scenario_id:
        return jsonify({"error": "scenarioId is required"}), 400
    
    # Get the full scenario with log content
    start_db = time.time()
    scenario = log_scenarios_collection.find_one({"id": scenario_id})
    duration = time.time() - start_db
    if hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator += duration
    
    if not scenario:
        # No fallback anymore, just return a 404 error
        return jsonify({"error": "Scenario not found"}), 404
        
    # Apply difficulty modifier to time limit
    time_modifiers = {
        'easy': 1.5,
        'medium': 1.0,
        'hard': 0.7
    }
    base_time_limit = scenario.get('timeLimit', 300)  # Default: 5 minutes
    modified_time_limit = int(base_time_limit * time_modifiers.get(difficulty, 1.0))
    
    # *** NEW CODE: Randomize threat options ***
    if 'threatOptions' in scenario:
        # Convert for manipulation (MongoDB objects may be immutable)
        threat_options = list(scenario['threatOptions'])
        # Shuffle the threat options randomly
        random.shuffle(threat_options)
        # Put back in scenario
        scenario['threatOptions'] = threat_options
    
    # Check if content exists, generate dummy content only if needed
    if 'logs' in scenario:
        for log in scenario['logs']:
            # Check if content array exists and has items
            if 'content' not in log or not isinstance(log['content'], list) or len(log['content']) == 0:
                # Generate some dummy content if none exists
                log['content'] = generate_dummy_log_content(log.get('type', 'generic'), 15)
    
    # If user_id is provided, record the start of this scenario
    if user_id:
        try:
            user_oid = ObjectId(user_id)
            
            # Get user data
            start_db = time.time()
            user = get_user_by_id(user_id)
            duration = time.time() - start_db
            if hasattr(g, 'db_time_accumulator'):
                g.db_time_accumulator += duration
            
            if user:
                # Record the start of this attempt
                attempt_data = {
                    "userId": user_oid,
                    "scenarioId": scenario_id,
                    "startTime": datetime.utcnow(),
                    "completed": False,
                    "difficulty": difficulty,
                    "timeLimit": modified_time_limit
                }
                
                start_db = time.time()
                log_analysis_collection.insert_one(attempt_data)
                duration = time.time() - start_db
                if hasattr(g, 'db_time_accumulator'):
                    g.db_time_accumulator += duration
        except Exception as e:
            print(f"Error recording scenario start: {e}")
    
    # Convert the MongoDB ObjectId to string for JSON
    if '_id' in scenario:
        scenario['_id'] = str(scenario['_id'])
    
    return jsonify({
        "scenario": scenario,
        "timeLimit": modified_time_limit
    })

@threat_hunter_bp.route('/submit-analysis', methods=['POST'])
def submit_analysis():
    """
    Submit a log analysis for scoring and evaluation.
    """
    data = request.json
    user_id = data.get('userId')
    scenario_id = data.get('scenarioId')
    flagged_lines = data.get('flaggedLines', [])
    detected_threats = data.get('detectedThreats', [])
    time_left = data.get('timeLeft', 0)
    
    if not user_id or not scenario_id:
        return jsonify({"error": "userId and scenarioId are required"}), 400
    
    try:
        user_oid = ObjectId(user_id)
    except:
        return jsonify({"error": "Invalid user ID"}), 400
    
    # Get user data
    start_db = time.time()
    user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator += duration
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Get scenario data
    start_db = time.time()
    scenario = log_scenarios_collection.find_one({"id": scenario_id})
    duration = time.time() - start_db
    if hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator += duration
    
    if not scenario:
        # No fallback anymore, just return a 404 error
        return jsonify({"error": "Scenario not found"}), 404
    
    # Evaluate the submission
    actual_threats = scenario.get('threats', [])
    suspicious_lines = scenario.get('suspiciousLines', [])
    
    # Calculate score
    max_score = 100
    base_score = 0
    time_bonus = 0
    
    # Check for correctly identified threats
    correct_threats = []
    missed_threats = []
    false_positives = []
    
    # Evaluate threats detected - FIXED to handle no detected threats case
    if not detected_threats:
        # If no threats detected, all actual threats are missed
        missed_threats = actual_threats.copy()
    else:
        # Evaluate the detected threats
        for actual_threat in actual_threats:
            found = False
            for detected_threat in detected_threats:
                # Simple matching for now - could be more sophisticated
                if detected_threat.get('type') == actual_threat.get('type') and detected_threat.get('name') == actual_threat.get('name'):
                    correct_threats.append(actual_threat)
                    found = True
                    break
            
            if not found:
                missed_threats.append(actual_threat)
        
        # Check for false positives
        for detected_threat in detected_threats:
            found = False
            for actual_threat in actual_threats:
                if detected_threat.get('type') == actual_threat.get('type') and detected_threat.get('name') == actual_threat.get('name'):
                    found = True
                    break
            
            if not found:
                false_positives.append(detected_threat)
    
    # Calculate base score
    if len(actual_threats) > 0:
        threat_score = (len(correct_threats) / len(actual_threats)) * 70  # 70% of score from threats
    else:
        threat_score = 70  # Full score if there are no actual threats to find
    
    # Check for correctly flagged suspicious lines
    # Convert suspiciousLines to a more uniform format for comparison
    formatted_suspicious_lines = []
    for line in suspicious_lines:
        if isinstance(line, dict) and 'logId' in line and 'lineIndex' in line:
            formatted_suspicious_lines.append(line)
        else:
            # Assuming line is just an index
            formatted_suspicious_lines.append({'lineIndex': line})
    
    flagged_correct = 0
    flagged_incorrect = 0
    
    for flagged_line in flagged_lines:
        found = False
        for suspicious_line in formatted_suspicious_lines:
            if 'logId' in flagged_line and 'logId' in suspicious_line:
                if flagged_line['logId'] == suspicious_line['logId'] and flagged_line['lineIndex'] == suspicious_line['lineIndex']:
                    found = True
                    break
            else:
                # For backward compatibility
                if flagged_line.get('lineIndex', flagged_line) == suspicious_line.get('lineIndex', suspicious_line):
                    found = True
                    break
        
        if found:
            flagged_correct += 1
        else:
            flagged_incorrect += 1
    
    if len(formatted_suspicious_lines) > 0:
        # 20% of score from correctly flagging suspicious lines
        flagging_score = min(20, (flagged_correct / len(formatted_suspicious_lines)) * 20)
    else:
        flagging_score = 20  # Full score if there are no suspicious lines
    
    # Penalize for false positives
    false_positive_penalty = min(30, len(false_positives) * 5 + flagged_incorrect * 2)
    
    # Calculate base score
    base_score = threat_score + flagging_score - false_positive_penalty
    base_score = max(0, base_score)  # Ensure score isn't negative
    
    # Add time bonus (up to 10 points)
    time_bonus = min(10, int(time_left / 10))
    
    # Final score
    total_score = min(max_score, base_score + time_bonus)
    
    # Award XP and coins based on score
    xp_awarded = int(total_score / 2)  # 1 XP for every 2 points
    coins_awarded = int(total_score / 5)  # 1 coin for every 5 points
    
    # Add bonuses for difficulty
    if data.get('difficulty') == 'hard':
        xp_awarded = int(xp_awarded * 1.5)
        coins_awarded = int(coins_awarded * 1.5)
    
    # Update user stats
    update_user_xp(user_id, xp_awarded)
    update_user_coins(user_id, coins_awarded)
    
    # Generate feedback based on performance
    feedback = generate_feedback(total_score, len(correct_threats), len(missed_threats), len(false_positives))
    
    # Record the completed analysis
    completion_data = {
        "userId": user_oid,
        "scenarioId": scenario_id,
        "completionTime": datetime.utcnow(),
        "score": total_score,
        "detectedThreats": detected_threats,
        "flaggedLines": flagged_lines,
        "correctThreats": len(correct_threats),
        "missedThreats": len(missed_threats),
        "falsePositives": len(false_positives)
    }
    
    start_db = time.time()
    log_analysis_collection.update_one(
        {"userId": user_oid, "scenarioId": scenario_id, "completed": False},
        {"$set": {
            "completed": True,
            "score": total_score,
            "detectedThreats": detected_threats,
            "flaggedLines": flagged_lines,
            "correctThreats": len(correct_threats),
            "missedThreats": len(missed_threats),
            "falsePositives": len(false_positives),
            "completionTime": datetime.utcnow()
        }}
    )
    duration = time.time() - start_db
    if hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator += duration
    
    # Check for achievements
    new_achievements = check_for_threat_hunter_achievements(user_id, total_score)
    
    # Prepare the response
    result = {
        "score": total_score,
        "maxScore": max_score,
        "correctThreats": [{"name": t.get("name", "Unknown Threat"), "description": t.get("description", "")} for t in correct_threats],
        "missedThreats": [{"name": t.get("name", "Unknown Threat"), "description": t.get("description", "")} for t in missed_threats],
        "falsePositives": [{"type": t.get("type", "unknown"), "description": t.get("description", "")} for t in false_positives],
        "timeBonus": time_bonus,
        "xpAwarded": xp_awarded,
        "coinsAwarded": coins_awarded,
        "feedback": feedback,
        "newAchievements": new_achievements
    }
    
    return jsonify(result)

def check_for_threat_hunter_achievements(user_id, score):
    """
    Check for any Threat Hunter game achievements unlocked by this submission.
    """
    # Here we'd implement specific achievement logic
    # For now, just return some sample achievements based on score
    achievements = []
    
    if score >= 90:
        achievements.append({
            "name": "Master Threat Hunter",
            "description": "Score 90+ in a Threat Hunter scenario"
        })
    elif score >= 75:
        achievements.append({
            "name": "Senior Analyst",
            "description": "Score 75+ in a Threat Hunter scenario"
        })
    
    # We can also check the database for other achievement conditions
    # like number of scenarios completed, etc.
    
    return achievements

def generate_feedback(score, correct_threats, missed_threats, false_positives):
    """
    Generate personalized feedback based on performance metrics.
    """
    if score >= 90:
        return "Outstanding analysis! You correctly identified almost all threats with minimal false positives. Your log analysis skills are exceptional."
    elif score >= 75:
        return f"Great work! You found {correct_threats} threats, though you missed {missed_threats}. Your attention to detail is strong, but continue practicing to reduce the {false_positives} false positives."
    elif score >= 60:
        return f"Good analysis. You identified {correct_threats} threats but missed {missed_threats}. Work on reducing your {false_positives} false positives by carefully validating your suspicions before escalating."
    elif score >= 40:
        return f"Decent effort. You found {correct_threats} threats but missed {missed_threats} and had {false_positives} false positives. Focus on recognizing threat patterns in logs and improving your accuracy."
    else:
        return f"You have room for improvement. You missed {missed_threats} threats and had {false_positives} false positives. Study common attack patterns and indicators of compromise to build your threat hunting skills."

def generate_dummy_log_content(log_type, num_lines):
    """
    Generate dummy log content based on log type.
    This ensures there's always something to display in the log viewer.
    """
    content = []
    if log_type == "auth":
        users = ["admin", "jsmith", "alice", "bob", "system", "root"]
        ips = ["192.168.1.50", "192.168.1.55", "10.0.0.5", "45.23.125.87", "127.0.0.1", "172.16.0.10"]
        actions = ["logged in", "failed login attempt", "password changed", "account locked", "session expired"]
        
        for i in range(num_lines):
            user = random.choice(users)
            ip = random.choice(ips)
            action = random.choice(actions)
            timestamp = f"2025-04-15T{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}Z"
            log_line = f"{timestamp} INFO [auth.service] {user} {action} from {ip}"
            content.append({"text": log_line})
            
    elif log_type == "system":
        services = ["system.service", "cron.service", "network.service", "disk.service", "security.service"]
        messages = [
            "System started",
            "Service restarted",
            "High CPU usage detected",
            "Low disk space warning",
            "New device connected",
            "User account created",
            "File access denied",
            "Process terminated",
            "Unexpected outbound connection",
            "Large file transfer detected"
        ]
        
        for i in range(num_lines):
            service = random.choice(services)
            message = random.choice(messages)
            level = random.choice(["INFO", "WARNING", "ERROR"])
            timestamp = f"2025-04-15T{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}Z"
            log_line = f"{timestamp} {level} [{service}] {message}"
            content.append({"text": log_line})
            
    elif log_type == "web":
        paths = ["/", "/admin", "/login", "/profile", "/settings", "/api/users", "/api/data", "/search"]
        methods = ["GET", "POST", "PUT", "DELETE"]
        status_codes = [200, 201, 301, 302, 400, 401, 403, 404, 500]
        
        for i in range(num_lines):
            ip = f"192.168.1.{random.randint(1, 254)}"
            path = random.choice(paths)
            method = random.choice(methods)
            status = random.choice(status_codes)
            size = random.randint(100, 10000)
            timestamp = f"[17/Apr/2025:{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d} +0000]"
            log_line = f"{ip} - - {timestamp} \"{method} {path} HTTP/1.1\" {status} {size} \"-\" \"Mozilla/5.0\""
            content.append({"text": log_line})
            
    else:
        for i in range(num_lines):
            timestamp = f"2025-04-15T{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}Z"
            log_line = f"{timestamp} INFO [generic.service] Log entry {i+1}"
            content.append({"text": log_line})
            
    return content

if __name__ == '__main__':
    pass
