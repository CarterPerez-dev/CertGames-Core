# helpers/celery_app.py

import os
import logging
from celery import Celery

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://redis:6379/0")


app = Celery(
    'tasks',
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND,
    broker_connection_retry_on_startup=True,
    include=['helpers.async_tasks', 'helpers.schedule_tasks']
)



app.conf.update({
    'worker_prefetch_multiplier': 1,  
    'task_acks_late': True, 
    'worker_concurrency': 8,         
})

app.autodiscover_tasks(['helpers'])


logger.info("Celery app initialized with broker %s", CELERY_BROKER_URL, CELERY_RESULT_BACKEND)

