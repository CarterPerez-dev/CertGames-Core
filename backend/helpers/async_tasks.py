# helpers/async_tasks.py

from celery import shared_task
from datetime import datetime, timedelta
import math
import logging

from helpers.celery_app import app
from mongodb.database import db

# ---------  AI Generation Imports  -----------
from helpers.analogy_helper import (
    generate_single_analogy as _generate_single_analogy,
    generate_comparison_analogy as _generate_comparison_analogy,
    generate_triple_comparison_analogy as _generate_triple_comparison_analogy
)

from helpers.scenario_helper import (
    generate_scenario as _generate_scenario,
    break_down_scenario as _break_down_scenario,
    generate_interactive_questions as _generate_interactive_questions  
)

from helpers.xploitcraft_helper import Xploits as _Xploits
from helpers.grc_helper import generate_grc_question as _generate_grc_question

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# -----------------------------
# Celery tasks for analogy
# -----------------------------

@app.task(bind=True, max_retries=3, default_retry_delay=10)
def generate_single_analogy_task(self, concept, category):
    try:
        return _generate_single_analogy(concept, category)
    except Exception as e:
        logger.error(f"Celery generate_single_analogy_task error: {e}")
        self.retry(exc=e)


@app.task(bind=True, max_retries=3, default_retry_delay=10)
def generate_comparison_analogy_task(self, concept1, concept2, category):
    try:
        return _generate_comparison_analogy(concept1, concept2, category)
    except Exception as e:
        logger.error(f"Celery generate_comparison_analogy_task error: {e}")
        self.retry(exc=e)


@app.task(bind=True, max_retries=3, default_retry_delay=10)
def generate_triple_comparison_analogy_task(self, concept1, concept2, concept3, category):
    try:
        return _generate_triple_comparison_analogy(concept1, concept2, concept3, category)
    except Exception as e:
        logger.error(f"Celery generate_triple_comparison_analogy_task error: {e}")
        self.retry(exc=e)


# -----------------------------
# Celery tasks for Scenario
# -----------------------------

@app.task(bind=True, max_retries=3, default_retry_delay=10)
def generate_scenario_task(self, industry, attack_type, skill_level, threat_intensity):
    """
    If _generate_scenario returns a streaming generator, we join it into one string 
    so that Celery can store/return that as the task result.
    """
    try:
        scenario_gen = _generate_scenario(industry, attack_type, skill_level, threat_intensity)
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
        return _break_down_scenario(scenario_text)
    except Exception as e:
        logger.error(f"Celery break_down_scenario_task error: {e}")
        self.retry(exc=e)


@app.task(bind=True, max_retries=3, default_retry_delay=10)
def generate_interactive_questions_task(self, scenario_text):
    """
    Gathers the chunked question output into a final string or JSON object.
    """
    try:
        questions_gen = _generate_interactive_questions(scenario_text)
        questions_text = "".join(questions_gen)
        return questions_text
    except Exception as e:
        logger.error(f"Celery generate_interactive_questions_task error: {e}")
        self.retry(exc=e)


# -----------------------------
# Celery tasks for Xploitcraft
# -----------------------------
_xploit = _Xploits()

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
        return _generate_grc_question(category, difficulty)
    except Exception as e:
        logger.error(f"Celery generate_grc_question_task error: {e}")
        self.retry(exc=e)


# -----------------------------
# Performance Metrics Aggregator
# -----------------------------
@shared_task
def aggregate_performance_metrics():
    """
    Runs (e.g. once per minute) to gather perfSamples from the past 5 minutes,
    compute average request time, DB query time, data transfer rate, throughput, etc.
    Then store in 'performanceMetrics'.

    Steps:
      1) Query perfSamples within the last 5 minutes.
      2) If none, do nothing.
      3) Summarize total requests, total duration, total DB time, total bytes, etc.
      4) Insert a doc in 'performanceMetrics'.
      5) Optionally cleanup old perfSamples to prevent infinite growth.
    """
    now = datetime.utcnow()
    five_min_ago = now - timedelta(minutes=5)

    # 1) Get all samples in last 5 minutes
    samples = list(db.perfSamples.find({"timestamp": {"$gte": five_min_ago}}))
    total_requests = len(samples)
    if total_requests == 0:
        # No data => no aggregator doc
        return

    # 2) Summation for our metrics
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

    # 3) Compute final aggregator stats
    avg_request_time = (total_duration / total_requests) if total_requests else 0
    avg_db_query_time = (total_db_time / total_requests) if total_requests else 0
    error_rate = (errors / total_requests) if total_requests else 0.0

    # data_transfer_rate => MB/s
    # We have total_bytes over total_duration (in seconds).
    data_transfer_rate_mb_s = 0.0
    if total_duration > 0:
        # Convert total bytes to MB => total_bytes / (1024*1024)
        # Then divide by total_duration
        data_transfer_rate_mb_s = (total_bytes / (1024.0 * 1024.0)) / total_duration

    # throughput => requests/min for that 5-minute window
    # total_requests / 5.0
    throughput = total_requests / 5.0

    # 4) Insert aggregator doc into performanceMetrics
    doc = {
        "avg_request_time": round(avg_request_time, 4),
        "avg_db_query_time": round(avg_db_query_time, 4),
        "data_transfer_rate": f"{data_transfer_rate_mb_s:.3f} MB/s",
        "throughput": round(throughput, 2),
        "error_rate": round(error_rate, 4),
        "timestamp": now
    }
    db.performanceMetrics.insert_one(doc)

    # 5) Cleanup old samples, e.g. older than 30 minutes
    thirty_min_ago = now - timedelta(minutes=30)
    db.perfSamples.delete_many({"timestamp": {"$lt": thirty_min_ago}})

    logger.info(
        f"Performance metrics aggregated @ {now} => requests={total_requests}, "
        f"avg_req_time={doc['avg_request_time']}s, db_time={doc['avg_db_query_time']}s, "
        f"throughput={doc['throughput']} req/min, data_rate={doc['data_transfer_rate']}, "
        f"error_rate={doc['error_rate']}"
    )

    return f"Aggregated {total_requests} samples; stored in performanceMetrics."

