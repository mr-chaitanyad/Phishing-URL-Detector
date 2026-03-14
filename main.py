from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import numpy as np
import re
from tensorflow.keras.models import load_model

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

model = load_model(r'C:\Users\User\OneDrive\Desktop\Phishing URL Detector\model\url_spam_detector.h5')
print("✅ Model loaded successfully!")

class URLRequest(BaseModel):
    url: str

def extract_features(url: str):
    url = str(url).lower().strip()
    features = [
        len(url),
        url.count('.'),
        url.count('-'),
        url.count('/'),
        sum(c.isdigit() for c in url),
        len(re.findall(r'[^a-z0-9.\-/:]', url)),
        1 if url.startswith('https') else 0,
        len(url.split('/')[2]) if '//' in url else len(url),
        1 if any(t in url for t in ['.tk','.xyz','.ru','.pw']) else 0,
        len(url.split('/')[-1]),
    ]
    return features

@app.get("/", response_class=HTMLResponse)
def home():
    with open("./frontend/index.html", "r", encoding="utf-8") as f:
        return f.read()
@app.post("/predict")
def predict(request: URLRequest):
    features   = np.array([extract_features(request.url)], dtype=np.float32)
    prediction = model.predict(features, verbose=0)[0][0]
    is_spam    = bool(prediction >= 0.5)
    confidence = float(prediction if is_spam else 1 - prediction)
    return {
        "url":        request.url,
        "prediction": "phishing" if is_spam else "safe",
        "confidence": round(confidence * 100, 2)
    }

@app.get("/predict")
def predict_get(url: str):
    features   = np.array([extract_features(url)], dtype=np.float32)
    prediction = model.predict(features, verbose=0)[0][0]
    is_spam    = bool(prediction >= 0.5)
    confidence = float(prediction if is_spam else 1 - prediction)
    return {
        "url":        url,
        "prediction": "phishing" if is_spam else "safe",
        "confidence": round(confidence * 100, 2)
    }