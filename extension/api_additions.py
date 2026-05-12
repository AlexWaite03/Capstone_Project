# FastAPI Additions for the Extension
#
# Two pieces need to be added to your existing api.py:
#   1. CORS middleware so the extension's chrome-extension:// origin can call you
#   2. A /scan wrapper endpoint that takes {type, value} and translates internally
#
# Drop the imports and middleware near the top of api.py (after `app = FastAPI(...)`),
# and drop the /scan route alongside your existing routes.

# ============================================================
# 1. CORS MIDDLEWARE
# ============================================================
# Add this import:
from fastapi.middleware.cors import CORSMiddleware

# And this immediately after `app = FastAPI(...)`:
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",                    # web app dev
        "https://your-app.com",                     # web app prod
        "chrome-extension://YOUR_EXTENSION_ID",     # fill in after first load
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# For initial development, you can use allow_origins=["*"] with
# allow_credentials=False. Tighten before deploying.


# ============================================================
# 2. /scan WRAPPER ENDPOINT
# ============================================================

class ScanRequest(BaseModel):
    type: str    # "URL" or "Email"
    value: str

class ScanResponse(BaseModel):
    percentage: int
    riskLabel: str
    details: Optional[Dict[str, Any]] = None


@app.post("/scan", response_model=ScanResponse)
def scan(request: ScanRequest):
    """
    UI-friendly wrapper around /detect. Takes a simple {type, value} body
    and translates to the internal automata_interface call.
    """
    if request.type == "URL":
        result = automata_interface(url=request.value, email_ctx=None)
    elif request.type == "Email":
        email_ctx = {
            "from_addr": "",
            "body_text": request.value,
        }
        result = automata_interface(url=None, email_ctx=email_ctx)
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scan type: {request.type}"
        )

    # ADJUST THIS based on what automata_interface() actually returns.
    # Currently assumes a 'score' field as a float 0-1 or int 0-100.
    raw_score = result.get("score") or result.get("probability") or 0
    percentage = (
        int(round(raw_score * 100)) if raw_score <= 1
        else int(round(raw_score))
    )

    if percentage >= 50:
        risk_label = "High Risk"
    elif percentage >= 10:
        risk_label = "Medium Risk"
    else:
        risk_label = "Low Risk"

    return ScanResponse(
        percentage=percentage,
        riskLabel=risk_label,
        details=result,
    )
