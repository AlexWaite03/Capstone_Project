# api.py
# ============================================================
# FastAPI endpoint for Hybrid Phishing Detector using Automata
#to run swagger ui using test branch structure:  uvicorn src.api.api:app --reload
# ============================================================

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from src.api.automata_interface import automata_interface
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
    features: List[float]

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

model = joblib.load("data/processed/phishing_model.joblib")

@app.post("/predict")
def predict(request: PredictRequest):
    """
    Predict if URL or email is phishing.
    - Either provide `features` (list of 24 numbers)
    - OR provide `url` / `email_ctx` to auto-extract features
    """
    
    if request.features:
        features = request.features
        if len(features) != 24:
            raise HTTPException(status_code=400, detail="Features must contain exactly 24 numbers")
    
    elif request.url or request.email_ctx:
        features_dict = automata_interface(url=request.url, email_ctx=request.email_ctx)
        try:
            features = [features_dict[f"feat{i}"] for i in range(1,25)]  
        except KeyError:
            raise HTTPException(status_code=500, detail="Automata interface did not return 24 features")
    
    else:
        raise HTTPException(status_code=400, detail="Provide either `features` or `url` / `email_ctx`")

    # Predict
    result = model.predict([features])
    return {"prediction": int(result[0])}

# -------------------------
# Health Check Endpoint
# -------------------------
@app.get("/health")
def health_check():
    return {"status": "ok", "message": "API is running"}

