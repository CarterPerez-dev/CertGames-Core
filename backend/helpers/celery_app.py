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
    'worker_prefetch_multiplier': 3,
    'task_acks_late': True,
    'worker_concurrency': 10,  # Match hyperthreaded core count
    'task_time_limit': 1000,    # 1 hour max task runtime
    'task_soft_time_limit': 800,  # 55 minutes soft limit
    'worker_max_tasks_per_child': 1000,  # Restart worker after 1000 tasks to prevent memory leaks
    'worker_max_memory_per_child': 400000,  # Restart if using more than 400MB
    'timezone': 'America/New_York',
    'enable_utc': True,
})

app.conf.beat_schedule = {
    'check-api-health-every-10-min': {
        'task': 'helpers.async_tasks.check_api_health',
        'schedule': crontab(minute='*/15')  
    },
    'aggregate-performance-every-3-mins': {
        'task': 'helpers.async_tasks.aggregate_performance_metrics',
        'schedule': 800.0,
    },
    'cleanup-logs-daily': {
        'task': 'helpers.async_tasks.cleanup_logs',
        'schedule': crontab(hour=3, minute=0),
    },
    'update-expired-subscriptions': {
        'task': 'helpers.async_tasks.update_expired_subscriptions',
        'schedule': crontab(hour='*/6'),
    },          
    'cleanup-logs-every-2-days': {
        'task': 'helpers.async_tasks.cleanup_logs',
        'schedule': crontab(hour=2, minute=0, day_of_month='*/2'), 
    },
}






app.autodiscover_tasks(['helpers'])

logger.info("Celery app initialized with broker %s and backend %s", CELERY_BROKER_URL, CELERY_RESULT_BACKEND)

