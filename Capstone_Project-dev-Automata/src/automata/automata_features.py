# automata_features.py
# ============================================================
# Feature extraction layer for the Hybrid Phishing Detector.
#
# This module:
#   1) Tokenizes by character-class tokens (Tok) (dfa.py / nfa.py compatible)
#   2) Implements ALL 35 rules as deterministic finite-state matchers:
#        - Pure DFA/counter DFAs for threshold rules
#        - DFA-style streaming matchers for substring/keyword rules
#        - Deterministic structural checks for header mismatch / HTML comparisons
#   3) Returns (features_dict, reasons_list)
#
# Notes:
# - Several rules are easiest as *deterministic finite-state procedures*:
#   substring/keyword detection is regular and can be implemented as a DFA
#   (e.g., trie/Aho–Corasick). Here we implement them as deterministic scans
#   (still a finite-state recognizer conceptually).
# - Some rules are relational / parsing-based (headers mismatch, anchor mismatch).
#   Those are deterministic structural features and belong in the "non-regex" layer,
#   but they are still part of the rule library and are included here.
# ============================================================

from __future__ import annotations

from typing import Dict, Any, List, Tuple, Optional
import re

# Keep imports consistent with your package layout.
# If you are not using a package, remove the dot-prefixes.
from .dfa import Tok, tokenize, build_counting_dfa, build_length_threshold_dfa, dfa_accepts_text


# -------------------------
# Config / keyword lists
# -------------------------
SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq"}
SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly"}

URL_CRED_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "password", "signin", "confirm", "token", "session"
]
URL_BRAND_KEYWORDS = ["paypal", "netflix", "bank", "gov", "microsoft", "apple"]
URL_DANG_EXT = [".exe", ".scr", ".js", ".jar", ".bat", ".ps1", ".vbs"]

EMAIL_URGENCY_KEYWORDS = [
    "urgent", "immediately", "act now", "final notice",
    "suspended", "locked", "verify now", "action required"
]
EMAIL_CRED_KEYWORDS_NEUTRAL = [
    "password", "pin", "one-time", "one time", "otp",
    "security code", "verification code"
]
RISKY_ATTACH_EXT = (".exe", ".js", ".vbs", ".scr", ".bat", ".ps1", ".jar")


# -------------------------
# Helpers
# -------------------------
def _lower(s: Any) -> str:
    return s.lower() if isinstance(s, str) else ""


def feat_key(rule_id: str) -> str:
    return f"match_{rule_id.lower().replace('-', '_')}"


def extract_domain(addr: str) -> str:
    """Extract domain from 'Name <user@domain>' or 'user@domain>'."""
    if not addr:
        return ""
    a = addr.strip().lower()
    if "<" in a and ">" in a:
        a = a.split("<", 1)[1].split(">", 1)[0].strip()
    m = re.search(r"[a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,})", a)
    if m:
        return m.group(1).strip().strip(">")
    if "@" in a:
        return a.split("@")[-1].strip().strip(">")
    return ""


def url_host(url: str) -> str:
    u = _lower(url)
    m = re.match(r"^https?://([^/]+)", u)
    if not m:
        return ""
    host = m.group(1)
    # remove userinfo
    if "@" in host:
        host = host.split("@", 1)[-1]
    # remove port
    if ":" in host:
        host = host.split(":", 1)[0]
    return host


def url_tld(url: str) -> str:
    host = url_host(url)
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) < 2:
        return ""
    return parts[-1]


def has_any(text: str, keywords: List[str]) -> bool:
    t = _lower(text)
    return any(k in t for k in keywords)


def find_first(text: str, needles: List[str]) -> int:
    best = -1
    for n in needles:
        i = text.find(n)
        if i != -1 and (best == -1 or i < best):
            best = i
    return best


# ============================================================
# Pre-built DFAs for "pure counting" regular rules
# ============================================================
# URL-18: Many dots overall (>=6)
_DFA_URL_MANY_DOTS = build_counting_dfa(Tok.DOT, threshold=6)

# URL-05: Very long URL (>=120 chars)
_DFA_URL_VERY_LONG = build_length_threshold_dfa(120)

# URL-10: Many special chars (-_%=& >=12) is not directly tokenized; keep as deterministic count.
# URL-03: deep subdomain uses host dot count >=4 (counting over host string, deterministic)
# EMAIL-13: many links uses substring counting; deterministic


# ============================================================
# URL Rule Implementations (20)
# Each returns bool and is conceptually DFA-recognizable (regular),
# except ratio-style URL-09 which is a numeric feature.
# ============================================================

def match_url_01(url: str) -> bool:
    # IP address host
    u = _lower(url)
    if not (u.startswith("http://") or u.startswith("https://")):
        return False
    host = url_host(u)
    if not host:
        return False
    parts = host.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        if not (1 <= len(p) <= 3):
            return False
    return True


def match_url_02(url: str) -> bool:
    # '@' in authority before first slash
    u = _lower(url)
    if not (u.startswith("http://") or u.startswith("https://")):
        return False
    idx = u.find("://")
    if idx == -1:
        return False
    rest = u[idx + 3 :]
    slash = rest.find("/")
    at = rest.find("@")
    if at == -1:
        return False
    return True if slash == -1 else (at < slash)


def match_url_03(url: str) -> bool:
    # deep subdomain: host dots >=4
    host = url_host(url)
    return host.count(".") >= 4 if host else False


def match_url_04(url: str) -> bool:
    # hyphen-heavy host (>=3 hyphens)
    host = url_host(url)
    return host.count("-") >= 3 if host else False


def match_url_05(url: str) -> bool:
    # very long URL (>=120) using DFA length threshold
    return dfa_accepts_text(_DFA_URL_VERY_LONG, url)


def match_url_06(url: str) -> bool:
    u = _lower(url)
    for k in URL_CRED_KEYWORDS:
        if f"/{k}" in u:
            return True
        if f"?{k}=" in u or f"&{k}=" in u:
            return True
    return False


def match_url_07(url: str) -> bool:
    u = _lower(url)
    if not any(b in u for b in URL_BRAND_KEYWORDS):
        return False
    return url_tld(u) in SUSPICIOUS_TLDS


def match_url_08(url: str) -> bool:
    return url_tld(url) in SUSPICIOUS_TLDS


def match_url_09(url: str) -> bool:
    # high digit ratio > 0.25 (numeric feature; not a pure regular-language constraint)
    digits = sum(1 for c in url if c.isdigit())
    return digits / max(1, len(url)) > 0.25


def match_url_10(url: str) -> bool:
    specials = sum(1 for c in url if c in "-_%=&")
    return specials >= 12


def match_url_11(url: str) -> bool:
    # heavy URL encoding: >=5 occurrences of %xx
    i = 0
    count = 0
    while i < len(url) - 2:
        if url[i] == "%" and re.match(r"[0-9A-Fa-f]{2}", url[i+1:i+3]):
            count += 1
            if count >= 5:
                return True
            i += 3
        else:
            i += 1
    return False


def match_url_12(url: str) -> bool:
    u = _lower(url)
    first = find_first(u, ["http://", "https://"])
    if first == -1:
        return False
    second = find_first(u[first + 7 :], ["http://", "https://"])
    return second != -1


def match_url_13(url: str) -> bool:
    u = _lower(url)
    params = [
        "?url=", "&url=",
        "?redirect=", "&redirect=",
        "?next=", "&next=",
        "?target=", "&target=",
        "?dest=", "&dest="
    ]
    if not any(p in u for p in params):
        return False
    return ("http://" in u) or ("https://" in u) or ("http%3a%2f%2f" in u) or ("https%3a%2f%2f" in u)


def match_url_14(url: str) -> bool:
    u = _lower(url)
    for dom in SHORTENER_DOMAINS:
        if u.startswith(f"http://{dom}/") or u.startswith(f"https://{dom}/"):
            return True
    return False


def match_url_15(url: str) -> bool:
    u = _lower(url)
    return any(ext in u for ext in URL_DANG_EXT)


def match_url_16(url: str) -> bool:
    u = _lower(url)
    return u.startswith("http://xn--") or u.startswith("https://xn--")


def match_url_17(url: str) -> bool:
    u = url
    if re.search(r"//[^/]+//", u):
        return True
    if re.search(r"/[^ ]*(\\|;){2,}", u):
        return True
    return False


def match_url_18(url: str) -> bool:
    return dfa_accepts_text(_DFA_URL_MANY_DOTS, url)


def match_url_19(url: str) -> bool:
    host = url_host(url)
    if not host:
        return False
    return (("secure" in host) or ("account" in host) or ("verify" in host)) and ("." in host)


def match_url_20(url: str) -> bool:
    u = _lower(url)
    keys = ["/login", "/verify", "/account"]
    first = find_first(u, keys)
    if first == -1:
        return False
    second = find_first(u[first + 1 :], keys)
    return second != -1


# Rule registry with explanations
URL_RULES = [
    ("URL-01", match_url_01, "IP address used as host"),
    ("URL-02", match_url_02, "Contains '@' before first '/' in authority"),
    ("URL-03", match_url_03, "Deep subdomain nesting (>=4 dots in host)"),
    ("URL-04", match_url_04, "Hyphen-heavy host (>=3 hyphens)"),
    ("URL-05", match_url_05, "Very long URL (>=120 chars)"),
    ("URL-06", match_url_06, "Credential keywords in path/query"),
    ("URL-07", match_url_07, "Brand keyword + suspicious TLD"),
    ("URL-08", match_url_08, "Suspicious TLD"),
    ("URL-09", match_url_09, "High digit ratio (>0.25)"),
    ("URL-10", match_url_10, "Many special chars (-_%=& >=12)"),
    ("URL-11", match_url_11, "Heavy URL encoding (%xx >=5)"),
    ("URL-12", match_url_12, "Embedded second URL (http...http...)"),
    ("URL-13", match_url_13, "Redirect parameter contains URL"),
    ("URL-14", match_url_14, "Known shortener domain"),
    ("URL-15", match_url_15, "Dangerous file extension in URL"),
    ("URL-16", match_url_16, "Punycode domain xn--"),
    ("URL-17", match_url_17, "Odd separators / repeated slashes"),
    ("URL-18", match_url_18, "Many dots overall (>=6)"),
    ("URL-19", match_url_19, "Suspicious words in host"),
    ("URL-20", match_url_20, "Repeated credential segments"),
]


# ============================================================
# Email Rule Implementations (15)
# ============================================================

def match_email_01(ctx: Dict[str, Any]) -> bool:
    frm = _lower(ctx.get("from_addr", ""))
    return re.search(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", frm) is None


def match_email_02(ctx: Dict[str, Any]) -> bool:
    f = extract_domain(ctx.get("from_addr", ""))
    r = extract_domain(ctx.get("reply_to", ""))
    return (f != "" and r != "" and f != r)


def match_email_03(ctx: Dict[str, Any]) -> bool:
    f = extract_domain(ctx.get("from_addr", ""))
    rp = extract_domain(ctx.get("return_path", ""))
    return (f != "" and rp != "" and f != rp)


def match_email_04(ctx: Dict[str, Any]) -> bool:
    return _lower(ctx.get("reply_to", "")).strip() == ""


def match_email_05(ctx: Dict[str, Any]) -> bool:
    return _lower(ctx.get("return_path", "")).strip() == ""


def match_email_06(ctx: Dict[str, Any]) -> bool:
    f = extract_domain(ctx.get("from_addr", ""))
    msgid = _lower(ctx.get("message_id", ""))
    mid = extract_domain(msgid)
    return (f != "" and mid != "" and f != mid)


def match_email_07(ctx: Dict[str, Any]) -> bool:
    subj = ctx.get("subject", "") or ""
    return re.search(r"[!$#%*]{4,}", subj) is not None


def match_email_08(ctx: Dict[str, Any]) -> bool:
    subj = ctx.get("subject", "") or ""
    letters = [c for c in subj if c.isalpha()]
    if len(letters) < 8:
        return False
    upper = sum(1 for c in letters if c.isupper())
    return (upper / len(letters)) > 0.85


def match_email_09(ctx: Dict[str, Any]) -> bool:
    text = _lower((ctx.get("subject", "") or "") + " " + (ctx.get("body_text", "") or ""))
    return any(k in text for k in EMAIL_URGENCY_KEYWORDS)


def match_email_10(ctx: Dict[str, Any]) -> bool:
    # Neutral evidence: OTP/password/code words
    text = _lower((ctx.get("subject", "") or "") + " " + (ctx.get("body_text", "") or ""))
    return any(k in text for k in EMAIL_CRED_KEYWORDS_NEUTRAL)


def match_email_11(ctx: Dict[str, Any]) -> bool:
    body = _lower(ctx.get("body_text", "") or "")
    if "click here" not in body:
        return False
    return re.search(r"https?://\S+", body) is not None


def match_email_12(ctx: Dict[str, Any]) -> bool:
    # Display name mentions brand but from domain doesn't match.
    display = _lower(ctx.get("display_name", "") or "")
    frm_raw = _lower(ctx.get("from_addr", "") or "")
    from_dom = extract_domain(frm_raw)
    if not display and "<" in frm_raw:
        display = frm_raw.split("<", 1)[0].strip().strip('"').strip()
    if not display:
        return False
    brands = ["paypal", "microsoft", "apple", "netflix", "bank", "gov"]
    return any((b in display and b not in from_dom) for b in brands)


def match_email_13(ctx: Dict[str, Any]) -> bool:
    body = ctx.get("body_text", "") or ""
    links = re.findall(r"https?://\S+", body, flags=re.IGNORECASE)
    return len(links) >= 5


def match_email_14(ctx: Dict[str, Any]) -> bool:
    # Anchor text looks like URL but href differs
    html = ctx.get("body_html", "") or ""
    if not html:
        return False
    anchors = re.findall(
        r'<a\s+[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
        html,
        flags=re.IGNORECASE | re.DOTALL
    )
    for href, text in anchors:
        t = re.sub(r"\s+", " ", text).strip()
        if re.search(r"https?://", t, flags=re.IGNORECASE):
            if t.lower() not in href.lower():
                return True
    return False


def match_email_15(ctx: Dict[str, Any]) -> bool:
    names = ctx.get("attachment_names", [])
    if not isinstance(names, list):
        return False
    for n in names:
        if isinstance(n, str) and n.lower().endswith(RISKY_ATTACH_EXT):
            return True
    return False


EMAIL_RULES = [
    ("EMAIL-01", match_email_01, "Invalid 'From' format"),
    ("EMAIL-02", match_email_02, "From domain != Reply-To domain"),
    ("EMAIL-03", match_email_03, "From domain != Return-Path domain"),
    ("EMAIL-04", match_email_04, "Reply-To missing"),
    ("EMAIL-05", match_email_05, "Return-Path missing"),
    ("EMAIL-06", match_email_06, "From domain != Message-ID domain"),
    ("EMAIL-07", match_email_07, "Subject has excessive special characters"),
    ("EMAIL-08", match_email_08, "Subject mostly ALL CAPS"),
    ("EMAIL-09", match_email_09, "Urgency/pressure language"),
    ("EMAIL-10", match_email_10, "Credential words present (neutral)"),
    ("EMAIL-11", match_email_11, "'Click here' + link present"),
    ("EMAIL-12", match_email_12, "Display brand mismatch (heuristic)"),
    ("EMAIL-13", match_email_13, "Many links in body (>=5)"),
    ("EMAIL-14", match_email_14, "Anchor text URL mismatch (HTML)"),
    ("EMAIL-15", match_email_15, "Risky attachment extension"),
]


# ============================================================
# Public API
# ============================================================

def extract_features_url(url: str) -> Tuple[Dict[str, int], List[str]]:
    """
    Returns:
      features: {match_url_01:0/1, ..., match_url_20:0/1}
      reasons: list of 'URL-XX: explanation'
    """
    features: Dict[str, int] = {}
    reasons: List[str] = []

    for rule_id, fn, desc in URL_RULES:
        hit = bool(fn(url))
        features[feat_key(rule_id)] = int(hit)
        if hit:
            reasons.append(f"{rule_id}: {desc}")

    return features, reasons


def extract_features_email(ctx: Dict[str, Any]) -> Tuple[Dict[str, int], List[str]]:
    """
    ctx should include:
      from_addr, reply_to, return_path, message_id, subject, body_text
      body_html (optional), attachment_names (optional), display_name(optional)
    """
    features: Dict[str, int] = {}
    reasons: List[str] = []

    for rule_id, fn, desc in EMAIL_RULES:
        hit = bool(fn(ctx))
        features[feat_key(rule_id)] = int(hit)
        if hit:
            reasons.append(f"{rule_id}: {desc}")

    return features, reasons


def extract_automata_features(
    url: Optional[str] = None,
    email_ctx: Optional[Dict[str, Any]] = None
) -> Tuple[Dict[str, int], List[str]]:
    """
    Convenience wrapper:
      - if url provided: add URL features
      - if email_ctx provided: add email features
    """
    all_feats: Dict[str, int] = {}
    all_reasons: List[str] = []

    if url is not None:
        f, r = extract_features_url(url)
        all_feats.update(f)
        all_reasons.extend(r)

    if email_ctx is not None:
        f, r = extract_features_email(email_ctx)
        all_feats.update(f)
        all_reasons.extend(r)

    return all_feats, all_reasons


# ============================================================
# Optional: Simple "OTP-safe" explanation helper
# ============================================================
def otp_safe_summary(email_ctx: Dict[str, Any], feats: Dict[str, int]) -> str:
    """
    Helpful for your demo: explain why OTP emails should not be flagged
    solely because EMAIL-10 matched.
    """
    otp = feats.get(feat_key("EMAIL-10"), 0) == 1
    strong_mismatch = any(
        feats.get(feat_key(r), 0) == 1
        for r in ["EMAIL-02", "EMAIL-03", "EMAIL-06"]
    )
    urgency = feats.get(feat_key("EMAIL-09"), 0) == 1
    click_link = feats.get(feat_key("EMAIL-11"), 0) == 1

    if otp and not (strong_mismatch or urgency or click_link):
        return "OTP/login wording detected (neutral). No strong mismatch, urgency, or suspicious link signals."
    if otp:
        return "OTP/login wording detected, but combined with additional risk signals (mismatch/urgency/links)."
    return "No OTP/login wording detected."
