from features_extraction import extract_features
import pandas as pd
from scipy.sparse import hstack, csr_matrix
import pickle
import numpy as np

# Load the trained vectorizer
with open('model/tfidf_vectorizer.sav', 'rb') as file:
    tfidf = pickle.load(file)

# Load the trained model
with open('model/phishing_url_detector.sav', 'rb') as file:
    model = pickle.load(file)

# FastAPI setup
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class URLRequest(BaseModel):
    url: str

@app.post("/api/v1/predict")
def predict_url(data: URLRequest):
    url = data.url

    # Extract features
    external_struct = pd.DataFrame([extract_features(url)])
    external_text = tfidf.transform([url]) # Also transform the single input URL
    external_combined = hstack([csr_matrix(external_struct.values), external_text])

    # Predict
    prob = model.predict_proba(external_combined)[:, 1]

    # Convert numpy values to Python native types
    prediction = bool(prob > 0.5)
    confidence = float(prob[0])  # Convert numpy.float64 to Python float

    return {
        "url_prediction": prediction,
        "url_confidence": confidence,
        "url": url
    }

