# automata_interface.py
# ============================================================
# interface for the Hybrid Phishing Detector.
# Directly wraps automata_features.py for ML or API use.
# ============================================================

from typing import Optional, Dict, Any, List
from src.automata.automata_features import extract_automata_features, feat_key

def automata_interface(
    url: Optional[str] = None,
    email_ctx: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Returns ML-ready feature dict from URL and/or email input.
    
    Args:
        url: Optional URL string.
        email_ctx: Optional dictionary with email fields:
            from_addr, reply_to, return_path, message_id,
            subject, body_text, body_html (opt), attachment_names (opt),
            display_name (opt)
    
    Returns:
        {
            "features": { "match_url_01":0/1, ..., "match_email_15":0/1 },
            "matched_rules": [ "URL-01", "EMAIL-09", ... ],
            "reasons": [ "URL-01: IP address used as host", ... ]
        }
    """
    # Extract features using automata_features.py
    features, reasons = extract_automata_features(url=url, email_ctx=email_ctx)
    
    # Extract matched rule IDs for convenience
    matched_rules = [r.split(":")[0] for r in reasons]
    
    return {
        "features": features,
        "matched_rules": matched_rules,
        "reasons": reasons
    }


