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

