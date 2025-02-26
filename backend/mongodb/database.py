# database.py
from flask import Flask
from flask_pymongo import PyMongo
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)

# MongoDB Connection
app.config["MONGO_URI"] = os.getenv("MONGO_URI")  
mongo = PyMongo(app)

db = mongo.db

# Existing collections
mainusers_collection = db.mainusers
shop_collection = db.shopItems
achievements_collection = db.achievements
tests_collection = db.tests

# NEW collections for attempts and correct answers:
testAttempts_collection = db.testAttempts
correctAnswers_collection = db.correctAnswers

# NEW collections for daily bonus and questions
dailyQuestions_collection = db.dailyQuestions
dailyAnswers_collection = db.dailyAnswers
