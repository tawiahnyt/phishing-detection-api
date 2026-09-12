from database import Feedback, SessionLocal
from features_extraction import extract_features
import pandas as pd
import joblib
import numpy as np
from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime
from pathlib import Path



# Load the trained model
model_path = Path("model/phishing_url_model.joblib")

with open(model_path, "rb") as file:
    model = joblib.load(file)

app = FastAPI()

class URLRequest(BaseModel):
    url: str

class URLFeedbackRequest(BaseModel):
    timestamp: str
    url: str
    detection_result: str
    user_label: str
    comments: str = ""


@app.get("/")
def hello():
    return {
        "message": "Hello World!",
    }


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
# (prediction_prob[:, 1]
    # Convert numpy values to Python native types
    prediction = bool(prob > 0.5)
    confidence = (prob[0])  # Convert numpy.float64 to Python float

    return {
        "url_prediction": prediction,
        "url_confidence": confidence,
        "url": url
    }


@app.post("/api/v1/feedback")
def predict_with_feedback(data: URLFeedbackRequest):

    url = data.url

    # Extract URL features
    external_struct = pd.DataFrame([
        extract_features(url)
    ])

    # Get probability of phishing
    prob = model.predict_proba(external_struct)[:, 1]
    probability = float(prob[0])

    # 0.5 threshold
    prediction = probability > 0.5

    # Model result
    model_result = "Malicious" if prediction else "Safe"

    # Connect to database
    db = SessionLocal()

    try:

        feedback = Feedback(
            timestamp=data.timestamp,
            url=url,
            detection_result=model_result,
            user_label=data.user_label,
            comments=data.comments
        )

        db.add(feedback)
        db.commit()
        db.refresh(feedback)

    finally:
        db.close()

    return {
        "message": "Thank you! Your feedback has been recorded."
    }
