# api.py
# ============================================================
# FastAPI endpoint for Hybrid Phishing Detector using Automata
#to run swagger ui using test branch structure:  uvicorn src.api.api:app --reload
# http://127.0.0.1:8000/docs  in browser
# ============================================================

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from src.api.automata_interface import automata_interface
from src.automata.automata_features import extract_automata_features 
import joblib

app = FastAPI(title="Hybrid Phishing Detector API", version="1.0")

# -------------------------
# Request Models
# -------------------------
class EmailContext(BaseModel):
    from_addr: str
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    message_id: Optional[str] = None
    subject: Optional[str] = None
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    attachment_names: Optional[List[str]] = Field(default_factory=list)
    display_name: Optional[str] = None

class FeatureRequest(BaseModel):
    url: Optional[str] = None
    email_ctx: Optional[EmailContext] = None

class PredictRequest(BaseModel):
    url: str | None = None
    email_text: str | None = None


class DetectionRequest(BaseModel):
    url: Optional[str] = None
    email_ctx: Optional[Dict[str, Any]] = None




# -------------------------
# Routes
# -------------------------
@app.post("/extract_features")
def extract_features(request: FeatureRequest) -> Dict[str, Any]:
    if request.url is None and request.email_ctx is None:
        raise HTTPException(status_code=400, detail="Provide either 'url' or 'email_ctx'")

    # Convert Pydantic EmailContext to dict for interface
    email_ctx_dict = request.email_ctx.model_dump() if request.email_ctx else None

    # Extract features
    result = automata_interface(url=request.url, email_ctx=email_ctx_dict)
    return result

@app.post("/detect")
def detect(request: DetectionRequest):

    result = automata_interface(
        url=request.url,
        email_ctx=request.email_ctx
    )

    return result

# Load models
url_model = joblib.load("data/processed/phishing_model.joblib")
email_model = joblib.load("data/processed/email_model.joblib")
tfidf_vectorizer = joblib.load("data/processed/tfidf_vectorizer.joblib")


@app.post("/predict")
def predict(request: PredictRequest):

    results = {}

    try:

        # -------------------------
        # URL PHISHING DETECTION
        # -------------------------
        if request.url:

            url = request.url

            #  Lexical features
            url_len = len(url)
            n_dots = url.count(".")
            n_hyphens = url.count("-")
            n_digits = sum(c.isdigit() for c in url)

            lexical_features = [
                url_len,
                n_dots,
                n_hyphens,
                n_digits
            ]

            # Automata rule features
            features, reasons = extract_automata_features(url=url)

            url_rule_features = [
                features.get(f"match_url_{i:02}", 0)
                for i in range(1, 21)
            ]

            #  Build feature vector (24 features)
            feature_vector = lexical_features + url_rule_features

            if len(feature_vector) != url_model.n_features_in_:
                raise HTTPException(status_code=500, detail="URL feature mismatch")

            #  ML prediction
            prediction = url_model.predict([feature_vector])[0]
            probability = url_model.predict_proba([feature_vector])[0][1]

            results["url_prediction"] = {
                "url": url,
                "is_phishing": bool(prediction),
                "confidence": float(probability),
                "matched_rules": reasons
            }

        # -------------------------
        # EMAIL PHISHING DETECTION
        # -------------------------
        if request.email_text:

            email_text = request.email_text

            # Build email context for automata rules
            email_ctx = {
                "body_text": email_text
            }

            # Automata email rules
            features, reasons = extract_automata_features(email_ctx=email_ctx)

            # TF-IDF vectorization (5000 features)
            vector = tfidf_vectorizer.transform([email_text])

        
            prediction = email_model.predict(vector)[0]
            probability = email_model.predict_proba(vector)[0][1]

            results["email_prediction"] = {
                "is_phishing": bool(prediction),
                "confidence": float(probability),
                "matched_rules": reasons
            }

        if not results:
            raise HTTPException(status_code=400, detail="No URL or email provided")

        return results 
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# -------------------------
# Health Check Endpoint
# -------------------------
@app.get("/health")
def health_check():
    return {"status": "ok", "message": "API is running"}


