###############################
# celery_app.py (UPDATED)
###############################
import os
import logging
from celery import Celery
from celery.schedules import crontab
from dotenv import load_dotenv
from datetime import datetime
import requests

load_dotenv()
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

logger.debug(f"SendGrid API Key: {SENDGRID_API_KEY}")

CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://redis:6379/0")

app = Celery(
    'tasks',
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND,
    broker_connection_retry_on_startup=True,
    include=[
        'helpers.async_tasks',
    ]
)

app.conf.update({
    'worker_prefetch_multiplier': 1,
    'task_acks_late': True,
    'worker_concurrency': 8,
    'timezone': 'America/New_York',
    'enable_utc': True,
})

app.conf.beat_schedule = {
    'aggregate-performance-every-3-mins': {
        'task': 'helpers.async_tasks.aggregate_performance_metrics',
        'schedule': 300.0,  # 5 minutes actually lol
    },
    # API health checks every 10 minutes
    'check-api-endpoints-every-5-min': {
        'task': 'helpers.async_tasks.check_api_endpoints',
        'schedule': crontab(minute='*/10')
    },
    #Log cleanup daily at 2 AM
    'cleanup-logs-daily': {
        'task': 'helpers.async_tasks.cleanup_logs',
        'schedule': crontab(hour=2, minute=0),
    },
    # subscription checks
    'update-expired-subscriptions': {
        'task': 'tasks.celery_tasks.update_expired_subscriptions',
        'schedule': crontab(hour='*/6'),  # Run every 6 hours to be safe
    },          
}






app.autodiscover_tasks(['helpers'])

logger.info("Celery app initialized with broker %s and backend %s", CELERY_BROKER_URL, CELERY_RESULT_BACKEND)

