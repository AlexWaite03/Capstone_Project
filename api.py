# api.py
# ============================================================
# FastAPI endpoint for Hybrid Phishing Detector using Automata
# ============================================================

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from automata_interface import automata_interface

app = FastAPI(title="Hybrid Phishing Detector API", version="1.0")

# -------------------------
# Request Models
# -------------------------
class EmailContext(BaseModel):
    from_addr: str
    reply_to: Optional[str] = ""
    return_path: Optional[str] = ""
    message_id: Optional[str] = ""
    subject: Optional[str] = ""
    body_text: Optional[str] = ""
    body_html: Optional[str] = ""
    attachment_names: Optional[List[str]] = []
    display_name: Optional[str] = ""

class FeatureRequest(BaseModel):
    url: Optional[str] = None
    email_ctx: Optional[EmailContext] = None

# -------------------------
# Routes
# -------------------------
@app.post("/extract_features")
def extract_features(request: FeatureRequest) -> Dict[str, Any]:
    if request.url is None and request.email_ctx is None:
        raise HTTPException(status_code=400, detail="Provide either 'url' or 'email_ctx'")

    # Convert Pydantic EmailContext to dict for interface
    email_ctx_dict = request.email_ctx.dict() if request.email_ctx else None

    # Extract features
    result = automata_interface(url=request.url, email_ctx=email_ctx_dict)
    return result

# -------------------------
# Health Check Endpoint
# -------------------------
@app.get("/health")
def health_check():
    return {"status": "ok", "message": "API is running"}

# -------------------------
# Example to run:
# uvicorn api:app --reload --port 8000
# -------------------------
