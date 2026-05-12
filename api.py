# api.py
# ============================================================
# FastAPI endpoint for Hybrid Phishing Detector using Automata
# ============================================================

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from automata_interface import automata_interface

app = FastAPI(title="Hybrid Phishing Detector API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",                    # web app dev
        #"https://your-app.com",                     # web app prod
        "chrome-extension://odiboohihaljhmfgeonnfiojclpeagjk",     # fill in after first load
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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

class DetectionRequest(BaseModel):
    url: Optional[str] = None
    email_ctx: Optional[Dict[str, Any]] = None

class ScanRequest(BaseModel):
    type: str    # "URL" or "Email"
    value: str

class ScanResponse(BaseModel):
    percentage: int
    riskLabel: str
    reasons: List[str] = Field(default_factory=list)
    matchedRules: List[str] = Field(default_factory=list)
    features: Optional[Dict[str, Any]] = None


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

@app.post("/detect")
def detect(request: DetectionRequest):

    result = automata_interface(
        url=request.url,
        email_ctx=request.email_ctx
    )

    matched_rules = result.get("matched_rules", [])
    
    if request.url:
        percentage = min(100, (len(matched_rules)/20) * 100 )
    else:
        percentage = min(100, (len(matched_rules)/15) * 100)

    if percentage >= 50:
        risk_label = "High Risk"
    elif percentage >= 10:
        risk_label = "Medium Risk"
    else:
        risk_label = "Low Risk"

    return {
        **result,
        "percentage": percentage,
        "riskLabel": risk_label,
    }

# -------------------------
# Health Check Endpoint
# -------------------------
@app.get("/health")
def health_check():
    return {"status": "ok", "message": "API is running"}

