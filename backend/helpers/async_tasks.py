from celery import shared_task
from datetime import datetime, timedelta
import math
import logging
import requests
from helpers.celery_app import app
from mongodb.database import db

# ---------  AI Generation Imports -----------
from helpers.analogy_stream_helper import generate_analogy_stream
from helpers.scenario_helper import (
    generate_scenario,
    break_down_scenario,
    generate_interactive_questions
)
from helpers.xploitcraft_helper import Xploits
from helpers.grc_stream_helper import generate_grc_question, generate_grc_questions_stream

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Initialize Xploits
_xploit = Xploits()

# -----------------------------
# Celery tasks for analogy
# -----------------------------

@app.task(bind=True, max_retries=3, default_retry_delay=10)
def generate_single_analogy_task(self, concept, category):
    """
    Generate a single analogy for the given concept and category.
    Uses the unified analogy_stream_helper for generation.
    """
    try:
        # Use the streaming generator but join the results into a single string
        stream_gen = generate_analogy_stream("single", concept, category=category)
        analogy_text = "".join(stream_gen)
        return analogy_text
    except Exception as e:
        logger.error(f"Celery generate_single_analogy_task error: {e}")
        self.retry(exc=e)


@app.task(bind=True, max_retries=3, default_retry_delay=10)
def generate_comparison_analogy_task(self, concept1, concept2, category):
    """
    Generate a comparison analogy between two concepts using the given category.
    Uses the unified analogy_stream_helper for generation.
    """
    try:
        # Use the streaming generator but join the results into a single string
        stream_gen = generate_analogy_stream("comparison", concept1, concept2, category=category)
        analogy_text = "".join(stream_gen)
        return analogy_text
    except Exception as e:
        logger.error(f"Celery generate_comparison_analogy_task error: {e}")
        self.retry(exc=e)


@app.task(bind=True, max_retries=3, default_retry_delay=10)
def generate_triple_comparison_analogy_task(self, concept1, concept2, concept3, category):
    """
    Generate a triple comparison analogy among three concepts using the given category.
    Uses the unified analogy_stream_helper for generation.
    """
    try:
        # Use the streaming generator but join the results into a single string
        stream_gen = generate_analogy_stream("triple", concept1, concept2, concept3, category=category)
        analogy_text = "".join(stream_gen)
        return analogy_text
    except Exception as e:
        logger.error(f"Celery generate_triple_comparison_analogy_task error: {e}")
        self.retry(exc=e)


# -----------------------------
# Celery tasks for Scenario
# -----------------------------

@app.task(bind=True, max_retries=3, default_retry_delay=10)
def generate_scenario_task(self, industry, attack_type, skill_level, threat_intensity):
    """
    If generate_scenario returns a streaming generator, we join it into one string 
    so that Celery can store/return that as the task result.
    """
    try:
        scenario_gen = generate_scenario(industry, attack_type, skill_level, threat_intensity)
        scenario_text = "".join(scenario_gen)  # Convert generator of strings into a single string
        return scenario_text
    except Exception as e:
        logger.error(f"Celery generate_scenario_task error: {e}")
        self.retry(exc=e)


@app.task(bind=True, max_retries=3, default_retry_delay=10)
def break_down_scenario_task(self, scenario_text):
    """
    Takes a scenario and 'breaks it down' into context, actors, timeline, etc.
    """
    try:
        return break_down_scenario(scenario_text)
    except Exception as e:
        logger.error(f"Celery break_down_scenario_task error: {e}")
        self.retry(exc=e)


@app.task(bind=True, max_retries=3, default_retry_delay=10)
def generate_interactive_questions_task(self, scenario_text):
    """
    Gathers the chunked question output into a final string or JSON object.
    """
    try:
        questions_gen = generate_interactive_questions(scenario_text)
        questions_text = "".join(questions_gen)
        return questions_text
    except Exception as e:
        logger.error(f"Celery generate_interactive_questions_task error: {e}")
        self.retry(exc=e)


# -----------------------------
# Celery tasks for Xploitcraft
# -----------------------------
@app.task(bind=True, max_retries=3, default_retry_delay=10)
def generate_exploit_payload_task(self, vulnerability, evasion_technique):
    try:
        return _xploit.generate_exploit_payload(vulnerability, evasion_technique)
    except Exception as e:
        logger.error(f"Celery generate_exploit_payload_task error: {e}")
        self.retry(exc=e)


# -----------------------------
# Celery tasks for GRC
# -----------------------------
@app.task(bind=True, max_retries=3, default_retry_delay=10)
def generate_grc_question_task(self, category, difficulty):
    try:
        return generate_grc_question(category, difficulty)
    except Exception as e:
        logger.error(f"Celery generate_grc_question_task error: {e}")
        self.retry(exc=e)


# -----------------------------
# Performance Metrics Aggregator
# -----------------------------
@shared_task
def aggregate_performance_metrics():
    """
    Runs every 3 minutes to gather perfSamples from the past 5 minutes,
    compute average request time, DB query time, data transfer rate, throughput, etc.
    Then store in 'performanceMetrics'. We'll keep the last 20 records in the front end.
    """

    now = datetime.utcnow()
    three_min_ago = now - timedelta(minutes=5)

    samples = list(db.perfSamples.find({"timestamp": {"$gte": three_min_ago}}))
    total_requests = len(samples)
    if total_requests == 0:
        return  # No aggregator doc if no data

    total_duration = 0.0
    total_db_time = 0.0
    total_bytes = 0
    errors = 0

    for s in samples:
        total_duration += s.get("duration_sec", 0.0)
        total_db_time += s.get("db_time_sec", 0.0)
        total_bytes += s.get("response_bytes", 0)
        if s.get("http_status", 200) >= 400:
            errors += 1

    avg_request_time = (total_duration / total_requests) if total_requests else 0
    avg_db_query_time = (total_db_time / total_requests) if total_requests else 0
    error_rate = (errors / total_requests) if total_requests else 0.0

    # data_transfer_rate in MB/s (numeric float)
    data_transfer_rate_mb_s = 0.0
    if total_duration > 0:
        data_transfer_rate_mb_s = (total_bytes / (1024.0 * 1024.0)) / total_duration

    # throughput => requests / 3min => convert to requests/min
    # total_requests / 3.0 => requests per minute if we polled 3-min block.
    throughput = (total_requests / 3.0)

    doc = {
        "avg_request_time": round(avg_request_time, 4),         # in seconds
        "avg_db_query_time": round(avg_db_query_time, 4),       # also in seconds, store raw for now
        "data_transfer_rate": round(data_transfer_rate_mb_s, 3),# float in MB/s, no label text
        "throughput": round(throughput, 2),                     # requests/min
        "error_rate": round(error_rate, 4),                     # fraction: 0.0 -> 1.0
        "timestamp": now
    }
    db.performanceMetrics.insert_one(doc)

    # Optionally remove older perfSamples beyond X minutes to save space
    # e.g. keep only 60 minutes in raw samples:
    sixty_min_ago = now - timedelta(minutes=60)
    db.perfSamples.delete_many({"timestamp": {"$lt": sixty_min_ago}})

    # (Optional) Also remove old performanceMetrics older than 2 hours, if desired:
    two_hours_ago = now - timedelta(hours=2)
    db.performanceMetrics.delete_many({"timestamp": {"$lt": two_hours_ago}})

    return f"Aggregated {total_requests} samples into performanceMetrics."

@app.task(bind=True, max_retries=3, default_retry_delay=10)
def check_api_endpoints(self):
    """
    Ping a small set of always-GET-friendly endpoints to confirm the Flask app is up.
    """
    endpoints = [
        "http://backend:5000/health",
        "http://backend:5000/test/achievements",
        "http://backend:5000/test/leaderboard"
    ]

    results = []
    now = datetime.utcnow()
    for ep in endpoints:
        try:
            r = requests.get(ep, timeout=5)
            status = r.status_code
            ok = (status < 400)
            results.append({"endpoint": ep, "status": status, "ok": ok})
        except Exception as e:
            results.append({"endpoint": ep, "status": "error", "ok": False, "error": str(e)})

    doc = {
        "checkedAt": now,
        "results": results
    }
    db.apiHealth.insert_one(doc)
    return True

# -----------------------------
# Cleanup logs for auditLogs & apiHealth
# -----------------------------
@shared_task
def cleanup_logs():
    """
    Removes old audit logs and apiHealth docs older than 3 days.
    Runs daily (per the schedule in celery_app).
    """
    now = datetime.utcnow()
    cutoff = now - timedelta(days=3)

    deleted_audit = db.auditLogs.delete_many({"timestamp": {"$lt": cutoff}})
    deleted_health = db.apiHealth.delete_many({"checkedAt": {"$lt": cutoff}})

    logger.info(f"Cleaned logs older than 3 days => auditLogs: {deleted_audit.deleted_count}, "
                f"apiHealth: {deleted_health.deleted_count}")

    return f"Cleanup complete: auditLogs={deleted_audit.deleted_count}, apiHealth={deleted_health.deleted_count}"
