# URL Phishing Detection API

A small FastAPI service that analyzes URLs and predicts whether they might be phishing attempts using a trained machine learning model (Random Forest) combined with TF-IDF text features and structural URL features.

Table of Contents
- About
- Features
- Project Structure
- Requirements
- Installation
- Running
- API Usage
- Model files
- Contributing
- License

## About

This repository provides a REST API to classify URLs as phishing or benign. The service extracts structural and textual features from the URL, vectorizes text-based parts using TF-IDF, and feeds features to a trained Random Forest classifier to return a prediction and confidence score.

## Features

- Structural URL features (lengths, counts, suspicious characters)
- Protocol and domain analysis (https usage, subdomain patterns, IP addresses)
- TF-IDF text features on URL tokens
- Ensemble prediction with confidence scores
- Simple REST API for easy integration

## Project Structure

```
url_api/
├── app.py                     # Main FastAPI application
├── features_extraction.py     # URL feature extraction logic
├── model/
│   ├── phishing_url_detector.sav  # Trained ML model
│   └── tfidf_vectorizer.sav  # Fitted TF-IDF vectorizer
└── requirements.txt           # Project dependencies
```

## Requirements

- Python 3.12+
- See requirements.txt for package versions (FastAPI, scikit-learn, pandas, numpy, uvicorn, etc.)

## Installation

1. Create a virtual environment:

```bash
python -m venv .venv
```

2. Activate it:

On macOS / Linux:
```bash
source .venv/bin/activate
```
On Windows:
```bash
.venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r url_api/requirements.txt
```

## Running the API

Start the server with uvicorn (module path points to the package folder):

```bash
uvicorn url_api.app:app --reload
```

The API will be available at: http://127.0.0.1:8000

Interactive docs:
- Swagger UI: http://127.0.0.1:8000/docs
- ReDoc: http://127.0.0.1:8000/redoc

## API Usage

POST /predict

Request body (JSON):

```json
{
  "url": "https://example.com"
}
```

Example curl:

```bash
curl -X POST "http://127.0.0.1:8000/predict" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

Example response:

```json
{
  "url_prediction": false,
  "url_confidence": 0.95,
  "url": "https://example.com"
}
```

Fields:
- url_prediction: true if predicted phishing, false otherwise
- url_confidence: model confidence score (0.0 - 1.0)
- url: original URL sent in the request

## Model files

Place the trained model artifacts in `url_api/model/`:
- `phishing_url_detector.sav` — trained Random Forest model
- `tfidf_vectorizer.sav` — fitted TF-IDF vectorizer

If you retrain models, update the files in that directory and ensure they remain compatible with the feature extraction code.

## Running locally & development notes

- Ensure model files are present before starting the server.
- If you change feature extraction, retrain and export the model and vectorizer.
- Add tests around `features_extraction.py` if you plan to refactor feature logic.

## Contributing

Contributions are welcome. Suggested workflow:

1. Fork the repository
2. Create a feature branch (e.g., `fix/readme`)
3. Make changes and add tests where applicable
4. Open a pull request describing your change

## License

This project is provided under the MIT License. See LICENSE for details.

---

If you'd like, I can:

- fix the uvicorn run command or other details to match your entrypoint if it's different (I tried `url_api.app:app` which matches the structure shown).
- add a short example of how the prediction payload is validated by FastAPI (request model) if you want request schema docs.
