##################################
# mongodb/database.py (mostly same)
##################################
from flask import Flask
from flask_pymongo import PyMongo
import os

app = Flask(__name__)
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
mongo = PyMongo(app)
db = mongo.db

mainusers_collection = db.mainusers
shop_collection = db.shopItems
achievements_collection = db.achievements
tests_collection = db.tests
testAttempts_collection = db.testAttempts
correctAnswers_collection = db.correctAnswers
dailyQuestions_collection = db.dailyQuestions
dailyAnswers_collection = db.dailyAnswers
supportThreads_collection = db.supportThreads
# For suspicious activity....unhackable is my last name
auditLogs_collection = db.auditLogs

