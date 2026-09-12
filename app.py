from features_extraction import extract_features
import pandas as pd
import pickle
import numpy as np
from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime
import csv
import os


# File to store user-submitted data
DATA_FILE = "user_submissions.csv"

# Ensure the file exists
if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "url", "detection_result", "user_label", "comments"])

# Load the trained model
with open('model/phishing_url_detector.sav', 'rb') as file:
    model = pickle.load(file)

app = FastAPI()

class URLRequest(BaseModel):
    url: str

class URLFeedbackRequest(BaseModel):
    timestamp: str
    url: str
    detection_result: str
    user_label: str
    comments: str = ""


@app.get("/api/v1/health")
def health():
    return {
        "health": "healthy",
        "time": datetime.now()
    }


@app.post("/api/v1/predict")
def predict_url(data: URLRequest):
    url = data.url

    # Extract features
    external_struct = pd.DataFrame([extract_features(url)])

    # Predict
    prob = model.predict_proba(external_struct)[:, 1]

    # Convert numpy values to Python native types
    prediction = bool(prob > 0.5)
    confidence = float(prob[0])  # Convert numpy.float64 to Python float

    return {
        "url_prediction": prediction,
        "url_confidence": confidence,
        "url": url
    }


@app.post("/api/v1/feedback")
def predict_with_feedback(data: URLFeedbackRequest):
    url = data.url

    # Extract URL features
    external_struct = pd.DataFrame([extract_features(url)])

    # Get probability of phishing/malicious URL
    prob = model.predict_proba(external_struct)[:, 1]

    probability = float(prob[0])

    # 0.5 threshold
    prediction = probability > 0.5

    # Convert model prediction to a readable result
    model_result = "Malicious" if prediction else "Safe"

    with open(DATA_FILE, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    data.timestamp,
                    url,
                    model_result,
                    data.user_label,
                    data.comments
                ])

    return {
        "message": "Thank you! Your feedback has been recorded."
    }
