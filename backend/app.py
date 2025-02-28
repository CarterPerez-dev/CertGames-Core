#ProxyAuthRequired/backend/app.py

from flask import Flask
from flask_socketio import SocketIO
from dotenv import load_dotenv
from flask_cors import CORS
from flask_session import Session
from pymongo import MongoClient
import redis
import os
import logging
from flask import request, jsonify
import time
from flask import g

# Import your existing routes
from routes.xploit_routes import xploit_bp
from routes.scenario_routes import scenario_bp
from routes.analogy_routes import analogy_bp
from routes.subscribe_routes import subscribe_bp
from routes.unsubscribe_routes import unsubscribe_bp
from routes.grc_routes import grc_bp
from routes.test_routes import api_bp
from routes.cracked_admin import cracked_bp
from routes.support_routes import support_bp


# IMPORTANT: Now import from models.py (not models.user_subscription)
from models.test import create_user, get_user_by_id, update_user_fields

from mongodb.database import db


CORS(app, supports_credentials=True)

load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
mongo_uri = os.getenv("MONGO_URI")

CRACKED_ADMIN_PASSWORD = os.getenv('CRACKED_ADMIN_PASSWORD', 'authkey')

client = MongoClient(mongo_uri)
db = client.get_database()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'flask_session:'
app.config['SESSION_REDIS'] = redis.StrictRedis(host='redis', port=6379, db=0)

REDIS_PASSWORD = os.getenv('REDIS_PASSWORD')
app.config['SESSION_REDIS'] = redis.StrictRedis(
    host='redis',
    port=6379,
    db=0,
    password=REDIS_PASSWORD
)

Session(app)

@app.route('/health')
def home():
    return 'Backend is running'

@app.before_request
def log_request_info():
    logger.info(f"Handling request to {request.path} with method {request.method}")

# Register all your blueprints
app.register_blueprint(xploit_bp, url_prefix='/payload')
app.register_blueprint(scenario_bp, url_prefix='/scenario')
app.register_blueprint(analogy_bp, url_prefix='/analogy')
app.register_blueprint(grc_bp, url_prefix='/grc')
app.register_blueprint(subscribe_bp, url_prefix='/subscribe')
app.register_blueprint(unsubscribe_bp, url_prefix='/unsubscribe')
app.register_blueprint(api_bp, url_prefix='/test')
app.register_blueprint(cracked_bp, url_prefix="/cracked")
app.register_blueprint(support_bp, url_prefix="/support")

##############################
# 1) BEFORE REQUEST
##############################
@app.before_request
def log_request_start():
    """
    1) Log the request path/method for debugging
    2) Capture request start time
    3) Initialize g.db_time_accumulator = 0.0
    """
    logger.info(f"Handling request to {request.path} (method {request.method})")
    g.request_start_time = time.time()
    g.db_time_accumulator = 0.0  # We reset this; measure_db_operation can add to it

##############################
# 2) AFTER REQUEST
##############################
@app.after_request
def log_request_end(response):
    """
    1) measure how long the request took
    2) find the DB time from g.db_time_accumulator
    3) measure response size
    4) insert doc in perfSamples
    """
    try:
        # 1) Duration
        duration_sec = time.time() - g.request_start_time

        # 2) DB time
        db_time_sec = getattr(g, 'db_time_accumulator', 0.0)

        # 3) Response size in bytes
        #    If you haven't set a content_length, you can do:
        response_size = 0
        if response.direct_passthrough is False and response.data:
            response_size = len(response.data)
        # Alternatively: if "Content-Length" in response.headers, parse that

        # 4) HTTP status
        http_status = response.status_code

        # 5) Insert doc
        doc = {
            "route": request.path,
            "method": request.method,
            "duration_sec": duration_sec,
            "db_time_sec": db_time_sec,
            "response_bytes": response_size,
            "http_status": http_status,
            "timestamp": datetime.utcnow()
        }
        db.perfSamples.insert_one(doc)

    except Exception as e:
        logger.warning(f"Failed to insert perfSample: {e}")

    return response


@socketio.on('connect')
def handle_connect():
    logger.info('Client connected')
    socketio.emit('message', {'data': 'Connected to server'})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
