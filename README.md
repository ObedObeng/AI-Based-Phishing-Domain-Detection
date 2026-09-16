# AI-Based Phishing Domain Detection

Live demo: https://ai-based-phishing-domain-detection-1.onrender.com/

A Flask-based web application that predicts whether a submitted domain or URL is phishing, suspicious, or safe using a trained machine learning model.

## Overview

This project uses a TensorFlow model to analyze URL characteristics and classify a URL based on suspicious patterns and extracted features. The app provides:

- URL input form
- phishing classification result
- domain IP lookup
- WHOIS creation date lookup
- clean and interactive web UI

## Tech Stack

- Python 3.9
- Flask
- TensorFlow 2.7
- NumPy
- python-whois
- Gunicorn
- Render for deployment

## Project Structure

- `app3.py` – Flask application entry point
- `API.py` – model prediction logic
- `Feature_Extractor.py` – feature extraction pipeline
- `Url_Features.py` – URL feature logic
- `Malicious_URL_Prediction.h5` – trained model
- `templates/` – HTML frontend templates
- `static/` – CSS and image assets
- `requirements.txt` – dependency list
- `render.yaml` – Render deployment configuration

## Local Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/ObedObeng/AI-Based-Phishing-Domain-Detection.git
   cd AI-Based-Phishing-Domain-Detection
   ```

2. Create and activate a virtual environment:

   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Run the app:

   ```bash
   python app3.py
   ```

5. Open the app in a browser:

   ```text
   http://localhost:5000
   ```

## Deployment

This project is configured for Render deployment.

### Render settings

- Python version: 3.9
- Start command:

  ```bash
  gunicorn app3:app --bind 0.0.0.0:$PORT
  ```

## Model Notes

The trained model file is included in the repository and is loaded dynamically relative to the app file path to make it portable across environments.

## License

This project is intended for educational and demonstration purposes.
