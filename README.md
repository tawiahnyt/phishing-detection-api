# URL Phishing Detection API

A high-performance FastAPI service that analyzes URLs to detect potential phishing and malicious websites using machine learning. The service extracts comprehensive lexical, structural, and information-theoretic (Shannon entropy) features from input URLs and evaluates them with a pre-trained Scikit-learn model, providing probability scores and feedback storage via PostgreSQL.

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Environment Configuration](#environment-configuration)
- [Installation & Setup](#installation--setup)
- [Running the API](#running-the-api)
- [API Documentation](#api-documentation)
  - [Root Status](#1-root-status)
  - [Health Check](#2-health-check)
  - [Predict URL](#3-predict-url)
  - [Submit Feedback](#4-submit-feedback)
- [Model Details](#model-details)
- [Deployment](#deployment)
- [License](#license)

---

## Overview

Phishing URLs often exhibit telltale signs such as abnormal character distributions, suspicious domain structures, excessive subdomains, or direct IP usage. This API ingests URLs, computes dozens of statistical and structural heuristics via `features_extraction.py`, and feeds them into a serialized machine learning pipeline (`model/phishing_url_model.joblib`) to deliver fast, deterministic risk assessments.

---

## Key Features

- **Advanced Feature Extraction**:
  - Shannon entropy calculation for domain/path randomness detection
  - IPv4 / IPv6 hostname identification and version classification
  - Length and character count heuristics (digits, hyphens, `@`, suspicious query params)
  - Protocol verification and URL component tokenization
- **Pre-trained ML Model**: Scikit-learn classification model serialized with `joblib`.
- **Feedback Collection Loop**: Persists verified user feedback and misclassification reports to PostgreSQL using SQLAlchemy ORM.
- **Auto-Generated Documentation**: Native Swagger UI and ReDoc OpenAPI documentation.
- **Serverless Ready**: Pre-configured for deployment with Vercel (`vercel.json`).

---

## Project Structure

```
phishing-detection-api/
├── app.py                         # FastAPI application routes & endpoints
├── database.py                    # SQLAlchemy database engine & Feedback model
├── features_extraction.py         # URL feature engineering & entropy extraction
├── model/
│   └── phishing_url_model.joblib  # Trained Scikit-learn model artifact
├── requirements.txt               # Pinned pip dependencies
├── pyproject.toml                 # Project metadata and build definitions
├── vercel.json                    # Vercel serverless deployment routing
├── .env.example                   # Sample environment variable template
└── README.md                      # Project documentation
```

---

## Prerequisites

- **Python**: 3.11 or higher
- **PostgreSQL**: Local or hosted database instance (e.g., Supabase, Neon, AWS RDS) for feedback storage.

---

## Environment Configuration

Create a `.env` file in the root directory based on `.env.example`:

```bash
cp .env.example .env
```

Configure your PostgreSQL connection string in `.env`:

```env
DATABASE_URL=postgresql+psycopg://username:password@localhost:5432/phishing_db
```

> [!NOTE]
> `database.py` uses `psycopg` (version 3) binary driver for PostgreSQL connectivity. Tables are automatically created if they do not exist on startup.

---

## Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/tawiahnyt/phishing-detection-api.git
   cd phishing-detection-api
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv .venv
   ```
   - On macOS/Linux:
     ```bash
     source .venv/bin/activate
     ```
   - On Windows:
     ```bash
     .venv\Scripts\activate
     ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## Running the API

Start the FastAPI application with `uvicorn`:

```bash
uvicorn app:app --reload --host 127.0.0.1 --port 8000
```

Once running, access:
- **Base API URL**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Alternative ReDoc UI**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

---

## API Documentation

### 1. Root Status
Verify API accessibility.

- **Method**: `GET`
- **Path**: `/`
- **Response**:
  ```json
  {
    "status": "ok",
    "message": "Phishing Detection API is running"
  }
  ```

---

### 2. Health Check
System liveness and current timestamp.

- **Method**: `GET`
- **Path**: `/api/v1/health`
- **Response**:
  ```json
  {
    "health": "healthy",
    "time": "2026-09-13T14:40:00.123456"
  }
  ```

---

### 3. Predict URL
Evaluate a URL for phishing likelihood.

- **Method**: `POST`
- **Path**: `/api/v1/predict`
- **Headers**: `Content-Type: application/json`
- **Request Body**:
  ```json
  {
    "url": "https://suspicious-security-update-login.com/auth"
  }
  ```

- **Example `curl`**:
  ```bash
  curl -X POST "http://127.0.0.1:8000/api/v1/predict" \
    -H "Content-Type: application/json" \
    -d '{"url": "https://suspicious-security-update-login.com/auth"}'
  ```

- **Response**:
  ```json
  {
    "url_prediction": true,
    "url_confidence": 0.892,
    "url": "https://suspicious-security-update-login.com/auth"
  }
  ```

- **Field Descriptions**:
  | Field | Type | Description |
  |---|---|---|
  | `url_prediction` | boolean | `true` if identified as phishing (> 0.5 probability), `false` if benign. |
  | `url_confidence` | float | Probability score between `0.0` and `1.0` indicating phishing likelihood. |
  | `url` | string | The URL analyzed in the request. |

---

### 4. Submit Feedback
Record human verification or correction for model retraining and audit logs.

- **Method**: `POST`
- **Path**: `/api/v1/feedback`
- **Headers**: `Content-Type: application/json`
- **Request Body**:
  ```json
  {
    "timestamp": "2026-09-13T14:42:00Z",
    "url": "https://suspicious-security-update-login.com/auth",
    "detection_result": "Malicious",
    "user_label": "Malicious",
    "comments": "Confirmed fake domain mimicking enterprise SSO portal."
  }
  ```

- **Example `curl`**:
  ```bash
  curl -X POST "http://127.0.0.1:8000/api/v1/feedback" \
    -H "Content-Type: application/json" \
    -d '{
      "timestamp": "2026-09-13T14:42:00Z",
      "url": "https://suspicious-security-update-login.com/auth",
      "detection_result": "Malicious",
      "user_label": "Malicious",
      "comments": "Confirmed fake domain mimicking enterprise SSO portal."
    }'
  ```

- **Response**:
  ```json
  {
    "message": "Thank you! Your feedback has been recorded."
  }
  ```

---

## Model Details

- **Location**: `model/phishing_url_model.joblib`
- **Model Framework**: Scikit-learn (loaded via `joblib`)
- **Input Dimensions**: Feature vectors generated by [features_extraction.py](file:///Users/tawiah/Python/phishing-detection-api/features_extraction.py), covering:
  - Lexical properties (URL length, hostname length, path length, query length)
  - Character frequencies (dots, hyphens, slashes, underscores, question marks, equal signs, @)
  - Shannon entropy scores (distribution randomness)
  - IP and protocol patterns (IPv4/IPv6 address hostnames, HTTPS usage)
- **Output**: Probability of phishing classification (`predict_proba`) using a 0.5 decision threshold.

---

## Deployment

### Vercel Serverless
The repository includes [vercel.json](file:///Users/tawiah/Python/phishing-detection-api/vercel.json) configured for `@vercel/python`:

1. Install the Vercel CLI:
   ```bash
   npm install -g vercel
   ```
2. Deploy:
   ```bash
   vercel
   ```
3. Set your production environment variable in the Vercel project dashboard:
   - `DATABASE_URL`: Your PostgreSQL connection string.

---

## License

This project is licensed under the MIT License.
