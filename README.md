
# URL Phishing Detection API

This project is a FastAPI-based web service that detects phishing URLs using machine learning. The service provides a REST API endpoint that analyzes URLs and determines whether they are potentially phishing attempts.

## Project Structure
```
url_api/
├── app.py                     # Main FastAPI application
├── features_extraction.py     # URL feature extraction logic
├── model/
│   ├── phishing_url_detector.sav  # Trained ML model
│   └── tfidf_vectorizer.sav  # Fitted TF-IDF vectorizer
└── requirements.txt          # Project dependencies
```

## Features

1. **URL Analysis**: Extracts various features from URLs including:
   - Basic structural features (URL length, domain length, path length)
   - Protocol analysis (HTTPS usage)
   - Character and symbol analysis
   - Structural red flags (IP addresses, suspicious characters)
   - Subdomain analysis
   - Suspicious keyword detection
   - TLD and file extension analysis

2. **Machine Learning Model**:
   - Uses Random Forest Classifier for prediction
   - Combines TF-IDF features with structural features
   - Provides confidence scores for predictions

3. **REST API Endpoint**:
   - POST `/predict` endpoint
   - Accepts JSON input with URL
   - Returns prediction results with confidence scores

## Technical Stack

- **Framework**: FastAPI
- **ML Libraries**: scikit-learn, pandas, numpy
- **Feature Engineering**: TF-IDF Vectorization, Custom Feature Extraction
- **Development Tools**: Python 3.12, uvicorn

## API Usage

The API accepts POST requests with JSON payload:
```json
{
    "url": "https://example.com"
}
```

Response format:
```json
{
    "url_prediction": true/false,
    "url_confidence": 0.95,
    "url": "https://example.com"
}
```

Where:
- `url_prediction`: `true` if the URL is suspected to be phishing, `false` otherwise
- `url_confidence`: Confidence score of the prediction (0-1)
- `url`: The original URL that was analyzed

The project uses a comprehensive set of dependencies managed through `requirements.txt`, including FastAPI, scikit-learn, pandas, and other necessary packages for machine learning and web service functionality.






          
# Running the URL Phishing Detection API

Here's how to set up and run the project:

## 1. Environment Setup

First, make sure you have Python 3.12 installed. Then, set up a virtual environment and install dependencies:

```bash
python -m venv .venv
```

Activate the virtual environment:

For Windows:
```bash
.venv\Scripts\activate
```

Install dependencies:
```bash
pip install -r requirements.txt
```

## 2. Project Structure
The project is already set up with the following structure:
- `app.py` - Main FastAPI application
- `features_extraction.py` - URL feature extraction logic
- `model/` - Contains trained models
  - `phishing_url_detector.sav` - Trained Random Forest model
  - `tfidf_vectorizer.sav` - Fitted TF-IDF vectorizer
- `requirements.txt` - Project dependencies

## 3. Running the API

Start the FastAPI server using uvicorn:
```bash
uvicorn app:app --reload
```

The API will be available at `http://127.0.0.1:8000`

## 4. Testing the API

You can test the API using curl, Postman, or any HTTP client. Here's an example using curl:

```bash
curl -X POST "http://127.0.0.1:8000/predict" -H "Content-Type: application/json" -d "{\"url\":\"https://example.com\"}"
```

Expected response:
```json
{
    "url_prediction": false,
    "url_confidence": 0.95,
    "url": "https://example.com"
}
```

## 5. API Documentation

FastAPI automatically generates interactive API documentation. After starting the server, you can access:
- Swagger UI: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`

## 6. Features

The API analyzes URLs based on multiple features:
- URL structure analysis
- Domain characteristics
- Presence of suspicious elements
- TF-IDF based text analysis
- Machine learning-based prediction

The response includes:
- Prediction (true = phishing, false = safe)
- Confidence score (0-1)
- Original URL

The model combines both structural features and TF-IDF vectorization for accurate phishing detection.
