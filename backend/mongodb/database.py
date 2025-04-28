##################################
# mongodb/database.py 
##################################
from flask import Flask
from flask_pymongo import PyMongo
import os

app = Flask(__name__)
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
mongo = PyMongo(app)
db = mongo.db


# I only decided to define these in this file not all the other colelctions though
mainusers_collection = db.mainusers
shop_collection = db.shopItems
achievements_collection = db.achievements
tests_collection = db.tests
testAttempts_collection = db.testAttempts
correctAnswers_collection = db.correctAnswers
dailyQuestions_collection = db.dailyQuestions
dailyAnswers_collection = db.dailyAnswers
supportThreads_collection = db.supportThreads
auditLogs_collection = db.auditLogs
honeypot_interactions = db.get_collection("honeypot_interactions")
c2_beacons = db.c2_beacons
harvested_credentials = db.harvested_credentials
exfiltrated_data = db.exfiltrated_data
c2_commands = db.c2_commands
c2_beacons = db.c2_beacons
c2_systems = db.c2_systems
c2_command_history = db.c2_command_history
c2_command_results = db.c2_command_results
harvested_credentials = db.harvested_credentials

