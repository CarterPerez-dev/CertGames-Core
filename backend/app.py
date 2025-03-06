import os
import logging
import time
import pytz
import redis
from datetime import datetime
from flask import Flask, g, request, jsonify, current_app
from flask_cors import CORS
from flask_session import Session
from flask_socketio import SocketIO, join_room, leave_room, emit
from pymongo import MongoClient
from dotenv import load_dotenv

# routes
from routes.xploit_routes import xploit_bp
from routes.scenario_routes import scenario_bp
from routes.analogy_routes import analogy_bp
from routes.grc_routes import grc_bp
from routes.test_routes import api_bp
from routes.cracked_admin import cracked_bp
from routes.support_routes import support_bp
from routes.admin_newsletter_routes import admin_news_bp

from models.test import create_user, get_user_by_id, update_user_fields
from mongodb.database import db

load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
mongo_uri = os.getenv("MONGO_URI")
CRACKED_ADMIN_PASSWORD = os.getenv('CRACKED_ADMIN_PASSWORD', 'authkey')
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD')
SECRET_KEY = os.getenv('SECRET_KEY', 'supersecret')

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

#######################################
# Initialize Flask & Related
#######################################
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY

# Setup CORS
CORS(app, supports_credentials=True)

# Setup SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", path="/api/socket.io")

# Setup Redis-based sessions
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'flask_session:'
app.config['SESSION_REDIS'] = redis.StrictRedis(host='redis', port=6379, db=0, password=REDIS_PASSWORD)

Session(app)

# Make socketio accessible from other files (avoids circular imports)
# so in support_routes.py you can do:
#   socketio = current_app.extensions['socketio']
app.extensions['socketio'] = socketio

@app.route('/health')
def home():
    return 'Backend is running'

@app.before_request
def log_request_info():
    logger.info(f"Handling request to {request.path} with method {request.method}")

# Register blueprints
app.register_blueprint(xploit_bp, url_prefix='/payload')
app.register_blueprint(scenario_bp, url_prefix='/scenario')
app.register_blueprint(analogy_bp, url_prefix='/analogy')
app.register_blueprint(grc_bp, url_prefix='/grc')
app.register_blueprint(api_bp, url_prefix='/test')
app.register_blueprint(cracked_bp, url_prefix="/cracked")
app.register_blueprint(support_bp, url_prefix="/support")
app.register_blueprint(admin_news_bp, url_prefix="/cracked")
###########################
# BEFORE REQUEST
###########################
@app.before_request
def log_request_start():
    g.request_start_time = time.time()
    g.db_time_accumulator = 0.0

###########################
# AFTER REQUEST
###########################
@app.after_request
def log_request_end(response):
    try:
        duration_sec = time.time() - g.request_start_time
        db_time_sec = getattr(g, 'db_time_accumulator', 0.0)
        response_size = 0
        if not response.direct_passthrough and response.data:
            response_size = len(response.data)
        http_status = response.status_code

        # Insert into perfSamples
        doc = {
            "route": request.path,
            "method": request.method,
            "duration_sec": duration_sec,
            "db_time_sec": db_time_sec,
            "response_bytes": response_size,
            "http_status": http_status,
            # Store in UTC
            "timestamp": datetime.utcnow()
        }
        db.perfSamples.insert_one(doc)
    except Exception as e:
        logger.warning(f"Failed to insert perfSample: {e}")
    return response

########################################################################
# Socket.IO event handlers
########################################################################
@socketio.on('connect')
def handle_connect():
    app.logger.info(f"Client connected: {request.sid}")
    socketio.emit('message', {'data': 'Connected to server'})

@socketio.on('join_thread')
def on_join_thread(data):
    thread_id = str(data.get('threadId'))  # Ensure string
    join_room(thread_id)
    app.logger.info(f"Client joined thread room: {thread_id}")

@socketio.on('leave_thread')
def on_leave_thread(data):
    """
    data = { "threadId": "abc123" }
    """
    thread_id = data.get('threadId')
    if thread_id:
        leave_room(thread_id)
        app.logger.info(f"Client left thread room: {thread_id}")

@socketio.on('admin_typing')
def on_admin_typing(data):
    """
    Broadcast to that thread's room that admin is typing
    """
    thread_id = data.get('threadId')
    if thread_id:
        app.logger.info(f"Admin started typing in thread room: {thread_id}")
        socketio.emit('admin_typing', {"threadId": thread_id}, room=thread_id)

@socketio.on('admin_stop_typing')
def on_admin_stop_typing(data):
    thread_id = data.get('threadId')
    if thread_id:
        app.logger.info(f"Admin stopped typing in thread room: {thread_id}")
        socketio.emit('admin_stop_typing', {"threadId": thread_id}, room=thread_id)


@socketio.on('admin_new_message')
def on_admin_new_message(data):
    thread_id = data.get('threadId')
    message = data.get('message')
    if thread_id and message:
        thread_id = str(thread_id)  # Ensure string
        app.logger.info(f"Admin sending message to thread room: {thread_id}")
        socketio.emit('new_message', {
            "threadId": thread_id,
            "message": message
        }, room=thread_id)

@socketio.on('user_typing')
def on_user_typing(data):
    """
    data = { "threadId": "..." }
    Let the admin see "User is typing..."
    """
    thread_id = data.get('threadId')
    if thread_id:
        app.logger.info(f"User started typing in thread room: {thread_id}")
        socketio.emit('user_typing', {"threadId": thread_id}, room=thread_id)

@socketio.on('user_stop_typing')
def on_user_stop_typing(data):
    """
    data = { "threadId": "..." }
    Let the admin see the user is no longer typing
    """
    thread_id = data.get('threadId')
    if thread_id:
        app.logger.info(f"User stopped typing in thread room: {thread_id}")
        socketio.emit('user_stop_typing', {"threadId": thread_id}, room=thread_id)

@socketio.on('join_user_room')
def handle_join_user_room(data):
    user_id = data.get('userId')
    if user_id:
        room_name = f"user_{user_id}"
        join_room(room_name)
        app.logger.info(f"User {user_id} joined personal room: {room_name}")

if __name__ == '__main__':
    # For local dev, run the SocketIO server
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)

