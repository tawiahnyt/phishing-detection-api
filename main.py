import streamlit as st
import re
import csv
import os
from urllib.parse import urlparse
from datetime import datetime
from features_extraction import extract_features
import pandas as pd
from scipy.sparse import hstack, csr_matrix
import pickle
import numpy as np

# File to store user-submitted data
DATA_FILE = "user_submissions.csv"

# Ensure the file exists
if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "url", "detection_result", "user_label", "comments"])

# Initialize session state
if 'analysis_done' not in st.session_state:
    st.session_state.analysis_done = False
if 'current_url' not in st.session_state:
    st.session_state.current_url = ""
if 'current_result' not in st.session_state:
    st.session_state.current_result = None

# --- Detection Logic ---
with open('model/tfidf_vectorizer.sav', 'rb') as file:
    tfidf = pickle.load(file)

# Load the trained model
with open('model/phishing_url_detector.sav', 'rb') as file:
    model = pickle.load(file)

def detect_phishing(url):
    # Extract features
    external_struct = pd.DataFrame([extract_features(url)])
    external_text = tfidf.transform([url]) # Also transform the single input URL
    external_combined = hstack([csr_matrix(external_struct.values), external_text])

    # Predict
    prob = model.predict_proba(external_combined)[:, 1]

    # Convert numpy values to Python native types
    prediction = bool(prob > 0.5)
    score = float(prob[0]) * 100
    reasons = []

    # Add reason based on score
    if score <= 50:
        reasons.append(f"Confidence Score: {score:.2f}% - Low risk detected")
    elif score <= 70:
        reasons.append(f"Confidence Score: {score:.2f}% - Medium risk detected")
    else:
        reasons.append(f"Confidence Score: {score:.2f}% - High risk detected")

    # Determine result based on score
    if score <= 50:
        return 'Safe', reasons
    elif score <= 70:
        return 'Suspicious', reasons
    else:
        return 'Dangerous', reasons

# --- Streamlit UI ---
st.set_page_config(page_title="Phishing Website Detector", layout="centered")

st.title("🔍 Phishing Website Detection Tool")
st.markdown("Enter a URL below to analyze its safety.")

url = st.text_input("Website URL", placeholder="https://example.com")

def analyze_url():
    if url:
        with st.spinner("Analyzing..."):
            result = detect_phishing(url)
            st.session_state.analysis_done = True
            st.session_state.current_url = url
            st.session_state.current_result = result[0]  # Store only the status
            return result
    return None, []

if st.button("Analyze"):
    result, details = analyze_url()
    if result:
        # Risk Display
        if result == 'Safe':
            st.success("✅ This website is *Safe*.")
        elif result == 'Suspicious':
            st.warning("⚠ This website is *Suspicious*.")
        else:
            st.error("🚨 This website is *Dangerous*.")

        with st.expander("Details"):
            for reason in details:
                st.markdown(f"- {reason}")

# --- User Feedback Form ---
if st.session_state.analysis_done:
    st.markdown("---")
    st.subheader("🧠 Help Us Improve")
    st.markdown("Do you think the detection is correct? Submit this URL to improve our model.")
    
    with st.form("feedback_form"):
        user_label = st.radio("How would you classify this site?", ["Safe", "Unsafe"])
        user_comment = st.text_area("Any comments? (Optional)")
        submit_feedback = st.form_submit_button("Submit Feedback")
        
        if submit_feedback:
            with open(DATA_FILE, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    datetime.now().isoformat(),
                    st.session_state.current_url,
                    st.session_state.current_result,
                    user_label,
                    user_comment
                ])
            st.success("✅ Thank you! Your feedback has been recorded.")

if not url:
    st.warning("Please enter a valid URL.")