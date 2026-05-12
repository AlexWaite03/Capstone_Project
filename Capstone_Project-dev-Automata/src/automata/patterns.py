from dataclasses import dataclass
from typing import Callable, Optional, Literal, Dict, Any, List, Tuple
import re
from urllib.parse import unquote

AppliesTo = Literal["url", "email_subject", "email_body", "email_headers", "email_html"]

@dataclass(frozen=True)
class PatternRule:
    rule_id: str
    name: str
    applies_to: AppliesTo
    description: str
    explanation: str
    severity: int = 1  # 1=weak, 2=medium, 3=strong
    regex: Optional[str] = None
    func: Optional[Callable[[Dict[str, Any]], bool]] = None

    def compile(self):
        return re.compile(self.regex, re.IGNORECASE) if self.regex else None


# -------------------------
# Helpers (email + parsing)
# -------------------------
def extract_domain(addr: str) -> str:
    if not addr:
        return ""
    addr = addr.strip().lower()
    # crude extraction from "Name <user@domain>"
    if "<" in addr and ">" in addr:
        addr = addr.split("<", 1)[1].split(">", 1)[0]
    if "@" not in addr:
        return ""
    return addr.split("@")[-1].strip().strip(">")

def safe_get(ctx: Dict[str, Any], key: str) -> str:
    v = ctx.get(key, "")
    return v if isinstance(v, str) else ""

def from_replyto_mismatch(ctx: Dict[str, Any]) -> bool:
    return extract_domain(safe_get(ctx, "from_addr")) != "" and \
           extract_domain(safe_get(ctx, "reply_to")) != "" and \
           extract_domain(safe_get(ctx, "from_addr")) != extract_domain(safe_get(ctx, "reply_to"))

def from_returnpath_mismatch(ctx: Dict[str, Any]) -> bool:
    return extract_domain(safe_get(ctx, "from_addr")) != "" and \
           extract_domain(safe_get(ctx, "return_path")) != "" and \
           extract_domain(safe_get(ctx, "from_addr")) != extract_domain(safe_get(ctx, "return_path"))

def from_messageid_mismatch(ctx: Dict[str, Any]) -> bool:
    from_dom = extract_domain(safe_get(ctx, "from_addr"))
    msgid = safe_get(ctx, "message_id").lower().strip()
    # message-id often like <random@domain>
    msg_dom = extract_domain(msgid) if msgid else ""
    return from_dom != "" and msg_dom != "" and from_dom != msg_dom

def header_missing(key: str) -> Callable[[Dict[str, Any]], bool]:
    def _inner(ctx: Dict[str, Any]) -> bool:
        return safe_get(ctx, key).strip() == ""
    return _inner

def subject_all_caps(ctx: Dict[str, Any]) -> bool:
    subj = safe_get(ctx, "subject")
    letters = [c for c in subj if c.isalpha()]
    if len(letters) < 8:
        return False
    upper = sum(1 for c in letters if c.isupper())
    return upper / max(1, len(letters)) > 0.85

def many_links(ctx: Dict[str, Any]) -> bool:
    body = safe_get(ctx, "body_text")
    links = re.findall(r"https?://\S+", body, flags=re.IGNORECASE)
    return len(links) >= 5  # keep weak; newsletters exist

def click_here_with_link(ctx: Dict[str, Any]) -> bool:
    body = safe_get(ctx, "body_text").lower()
    return ("click here" in body) and bool(re.search(r"https?://\S+", body, flags=re.IGNORECASE))

def anchor_href_mismatch(ctx: Dict[str, Any]) -> bool:
    html = safe_get(ctx, "body_html")
    if not html:
        return False
    # very simple heuristic: anchor text looks like a URL but href differs
    anchors = re.findall(r'<a\s+[^>]*href="([^"]+)"[^>]*>(.*?)</a>', html, flags=re.IGNORECASE|re.DOTALL)
    for href, text in anchors:
        text_clean = re.sub(r"\s+", " ", text).strip()
        if re.search(r"https?://", text_clean, re.IGNORECASE):
            if text_clean.lower() not in href.lower():
                return True
    return False

def has_risky_attachment(ctx: Dict[str, Any]) -> bool:
    # if your dataset provides attachment names; otherwise leave false
    names = ctx.get("attachment_names", [])
    if not isinstance(names, list):
        return False
    risky = (".exe", ".js", ".vbs", ".scr", ".bat", ".ps1", ".jar")
    return any(isinstance(n, str) and n.lower().endswith(risky) for n in names)


# -------------------------
# URL feature helpers
# -------------------------
SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq"}  # can expand
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly"}

def url_has_suspicious_tld(url: str) -> bool:
    m = re.search(r"\.([a-z]{2,})(/|$)", url.lower())
    return bool(m and m.group(1) in SUSPICIOUS_TLDS)

def url_shortener(url: str) -> bool:
    return any(re.match(rf"^https?://{re.escape(dom)}/", url.lower()) for dom in SHORTENERS)

def url_many_dots(url: str) -> bool:
    return url.count(".") >= 6

def url_deep_subdomain(url: str) -> bool:
    # heuristic: host has many dots before first slash
    m = re.match(r"^https?://([^/]+)/?", url.lower())
    if not m:
        return False
    host = m.group(1)
    return host.count(".") >= 4

def url_embedded_url(url: str) -> bool:
    return bool(re.search(r"https?://.*https?://", url, re.IGNORECASE))

def url_redirect_param(url: str) -> bool:
    u = url.lower()
    return bool(re.search(r"(\?|&)(url|redirect|next|target|dest)=", u)) and \
           (("http%3a%2f%2f" in u) or ("http://" in u) or ("https://" in u))

def url_heavy_encoding(url: str) -> bool:
    return len(re.findall(r"%[0-9a-fA-F]{2}", url)) >= 5


# -------------------------
# Rule lists
# -------------------------
URL_RULES: List[PatternRule] = [
    PatternRule("URL-01", "IP address in host", "url",
        "Detects URLs using an IP address instead of a domain.",
        "This link uses an IP address as the website address, which is common in suspicious links.",
        severity=2,
        regex=r"^https?://(\d{1,3}\.){3}\d{1,3}([/:]|$)"
    ),
    PatternRule("URL-02", "@ in authority", "url",
        "Detects '@' before the first slash (can hide the real destination).",
        "This link contains an '@' before the first '/', which can hide the real destination domain.",
        severity=3,
        regex=r"^https?://[^/]*@"
    ),
    PatternRule("URL-03", "Deep subdomain", "url",
        "Detects unusually deep subdomain nesting.",
        "This link has many subdomains, which is a common trick used to impersonate legitimate sites.",
        severity=2,
        func=lambda ctx: url_deep_subdomain(ctx["url"])
    ),
    PatternRule("URL-04", "Hyphen-heavy host", "url",
        "Detects many hyphens in the host name.",
        "This link’s domain contains many hyphens, which can be used to mimic brand names.",
        severity=2,
        regex=r"^https?://[^/]*([a-z0-9]+-){3,}[a-z0-9]+(\.|/)"
    ),
    PatternRule("URL-05", "Very long URL", "url",
        "Detects unusually long URLs (feature-based).",
        "This link is unusually long, which is common in obfuscated or tracking-heavy scam links.",
        severity=1,
        func=lambda ctx: len(ctx["url"]) >= 120
    ),
    PatternRule("URL-06", "Credential keywords", "url",
        "Detects login/verify/account keywords in path or query.",
        "This link contains common credential-related keywords often used in phishing pages.",
        severity=2,
        regex=r"/(login|verify|update|secure|account|password|signin|confirm)\b|(\?|&)(login|verify|token|session|password)="
    ),
    PatternRule("URL-07", "Brand keyword + suspicious TLD", "url",
        "Detects brand-like keywords combined with high-abuse TLDs.",
        "This link mixes brand-related words with a TLD often abused by scammers.",
        severity=2,
        regex=r"\b(paypal|netflix|bank|gov|microsoft|apple)\b.*\.(tk|ml|ga|cf|gq)\b"
    ),
    PatternRule("URL-08", "Suspicious TLD", "url",
        "Detects high-abuse TLDs.",
        "This link uses a TLD that is frequently abused for scams.",
        severity=1,
        func=lambda ctx: url_has_suspicious_tld(ctx["url"])
    ),
    PatternRule("URL-09", "High digit density", "url",
        "Detects URLs with many digits (feature-based).",
        "This link contains an unusually high number of digits, which can indicate auto-generated scam URLs.",
        severity=1,
        func=lambda ctx: sum(c.isdigit() for c in ctx["url"]) / max(1, len(ctx["url"])) > 0.25
    ),
    PatternRule("URL-10", "Many special characters", "url",
        "Detects high count of special characters (feature-based).",
        "This link contains many special characters, often used to confuse users or hide content.",
        severity=1,
        func=lambda ctx: sum(c in "-_%=&" for c in ctx["url"]) >= 12
    ),
    PatternRule("URL-11", "Heavy URL encoding", "url",
        "Detects repeated %xx encoding.",
        "This link contains heavy URL encoding, which can be used to hide the true destination.",
        severity=2,
        func=lambda ctx: url_heavy_encoding(ctx["url"])
    ),
    PatternRule("URL-12", "Embedded URL", "url",
        "Detects multiple http/https occurrences (embedded URL).",
        "This link contains another full URL inside it, which is common in redirects or obfuscation.",
        severity=2,
        func=lambda ctx: url_embedded_url(ctx["url"])
    ),
    PatternRule("URL-13", "Redirect parameter", "url",
        "Detects redirect parameters that contain a URL.",
        "This link appears to redirect to another URL, which scammers use to hide the final destination.",
        severity=2,
        func=lambda ctx: url_redirect_param(ctx["url"])
    ),
    PatternRule("URL-14", "Known shortener", "url",
        "Detects known URL shortener domains.",
        "This link uses a URL shortener, which can hide the real destination.",
        severity=1,
        func=lambda ctx: url_shortener(ctx["url"])
    ),
    PatternRule("URL-15", "Risky file extension", "url",
        "Detects executable/script extensions in URL paths.",
        "This link points to a risky file type, which can be used to deliver malware.",
        severity=3,
        regex=r"\.(exe|scr|js|jar|bat|ps1|vbs)(\?|$)"
    ),
    PatternRule("URL-16", "Punycode domain", "url",
        "Detects xn-- punycode domains.",
        "This link uses punycode, which can be used for look-alike domains.",
        severity=2,
        regex=r"^https?://xn--"
    ),
    PatternRule("URL-17", "Odd separators", "url",
        "Detects unusual separators or repeated slashes.",
        "This link uses unusual separators, which can indicate obfuscation.",
        severity=1,
        regex=r"//[^/]+//|/[^ ]*(\\|;){2,}"
    ),
    PatternRule("URL-18", "Many dots overall", "url",
        "Detects very high dot count.",
        "This link contains many dots, which can indicate suspicious nesting or obfuscation.",
        severity=1,
        func=lambda ctx: url_many_dots(ctx["url"])
    ),
    PatternRule("URL-19", "Suspicious words in host", "url",
        "Detects words like secure/account/verify in the host.",
        "This link’s domain name uses words like 'secure' or 'verify' to appear trustworthy.",
        severity=1,
        regex=r"^https?://[^/]*(secure|account|verify)[^/]*\.[a-z]{2,}"
    ),
    PatternRule("URL-20", "Repeated credential segments", "url",
        "Detects repeated credential-related segments in path.",
        "This link repeats credential-related segments, which can be a sign of phishing page structure.",
        severity=1,
        regex=r"/(login|verify|account).*(/login|/verify|/account)"
    ),
]

EMAIL_RULES: List[PatternRule] = [
    PatternRule("EMAIL-01", "Invalid From format", "email_headers",
        "Validates From header format.",
        "The sender address format looks invalid or unusual.",
        severity=1,
        regex=r"^.*@.*\..*$"
    ),
    PatternRule("EMAIL-02", "From vs Reply-To mismatch", "email_headers",
        "From domain differs from Reply-To domain.",
        "The visible sender domain does not match the reply-to domain, which can be suspicious.",
        severity=3,
        func=from_replyto_mismatch
    ),
    PatternRule("EMAIL-03", "From vs Return-Path mismatch", "email_headers",
        "From domain differs from Return-Path domain.",
        "The visible sender domain does not match the return-path domain, which can be suspicious.",
        severity=3,
        func=from_returnpath_mismatch
    ),
    PatternRule("EMAIL-04", "Reply-To missing", "email_headers",
        "Reply-To header is missing.",
        "The Reply-To header is missing. On its own this is not proof of phishing, but it can add risk.",
        severity=1,
        func=header_missing("reply_to")
    ),
    PatternRule("EMAIL-05", "Return-Path missing", "email_headers",
        "Return-Path header is missing.",
        "The Return-Path header is missing. On its own this is not proof of phishing, but it can add risk.",
        severity=1,
        func=header_missing("return_path")
    ),
    PatternRule("EMAIL-06", "From vs Message-ID mismatch", "email_headers",
        "From domain differs from Message-ID domain.",
        "The sender domain does not match the message-id domain, which can be suspicious.",
        severity=2,
        func=from_messageid_mismatch
    ),
    PatternRule("EMAIL-07", "Subject special characters", "email_subject",
        "Detects excessive special characters in subject.",
        "The subject contains many special characters, which is common in scam-style messages.",
        severity=1,
        regex=r"[!$#%*]{4,}"
    ),
    PatternRule("EMAIL-08", "Subject mostly ALL CAPS", "email_subject",
        "Detects subject that is mostly uppercase.",
        "The subject is mostly uppercase, which can indicate pressure tactics.",
        severity=1,
        func=subject_all_caps
    ),
    PatternRule("EMAIL-09", "Urgency language", "email_body",
        "Detects urgency/pressure phrases.",
        "This message uses urgent language, which is a common social-engineering tactic.",
        severity=1,
        regex=r"\b(urgent|immediately|act now|final notice|suspended|locked|verify now)\b"
    ),
    PatternRule("EMAIL-10", "Credential-related words (neutral)", "email_body",
        "Detects password/OTP/code wording (neutral evidence).",
        "This message contains credential-related words. This is common in both legitimate OTP emails and scams, so it must be combined with other signals.",
        severity=1,
        regex=r"\b(password|pin|one[- ]time|otp|security code|verification code)\b"
    ),
    PatternRule("EMAIL-11", "Click here + link", "email_body",
        "Detects 'click here' plus a link.",
        "This message asks you to click a link, which can be risky depending on other signals.",
        severity=1,
        func=click_here_with_link
    ),
    PatternRule("EMAIL-12", "Display-name brand mismatch (heuristic)", "email_headers",
        "Detects brand-like display name with non-matching sender domain (heuristic).",
        "The display name suggests a brand, but the sender domain may not match. This can indicate impersonation.",
        severity=2,
        # Implement later if you store display name separately; keep placeholder:
        func=lambda ctx: False
    ),
    PatternRule("EMAIL-13", "Many links", "email_body",
        "Detects emails with many links.",
        "This message contains many links. This is common in newsletters but can also indicate scams.",
        severity=1,
        func=many_links
    ),
    PatternRule("EMAIL-14", "Anchor text mismatch (HTML)", "email_html",
        "Detects anchor text that looks like a URL but href differs.",
        "The visible link text does not match the real link destination, which can be used to trick users.",
        severity=2,
        func=anchor_href_mismatch
    ),
    PatternRule("EMAIL-15", "Risky attachment extension", "email_headers",
        "Detects risky attachment file types.",
        "This message contains a risky attachment type often used to deliver malware.",
        severity=3,
        func=has_risky_attachment
    ),
]

def apply_rules_to_url(url: str) -> Tuple[Dict[str, int], List[str]]:
    ctx = {"url": url}
    features: Dict[str, int] = {}
    reasons: List[str] = []

    for rule in URL_RULES:
        hit = False
        if rule.regex:
            hit = bool(re.search(rule.regex, url, re.IGNORECASE))
        elif rule.func:
            hit = bool(rule.func(ctx))

        features[f"match_{rule.rule_id.lower().replace('-', '_')}"] = int(hit)
        if hit:
            reasons.append(f"{rule.rule_id}: {rule.explanation}")

    return features, reasons

def apply_rules_to_email(ctx: Dict[str, Any]) -> Tuple[Dict[str, int], List[str]]:
    # ctx must have subject/body_text/body_html/from_addr/reply_to/return_path/message_id
    features: Dict[str, int] = {}
    reasons: List[str] = []

    subj = safe_get(ctx, "subject")
    body = safe_get(ctx, "body_text")
    html = safe_get(ctx, "body_html")

    for rule in EMAIL_RULES:
        hit = False
        if rule.applies_to == "email_subject":
            target = subj
            if rule.regex:
                hit = bool(re.search(rule.regex, target, re.IGNORECASE))
            elif rule.func:
                hit = bool(rule.func(ctx))
        elif rule.applies_to == "email_body":
            target = body
            if rule.regex:
                hit = bool(re.search(rule.regex, target, re.IGNORECASE))
            elif rule.func:
                hit = bool(rule.func(ctx))
        elif rule.applies_to == "email_html":
            if rule.func:
                hit = bool(rule.func(ctx))
            elif rule.regex:
                hit = bool(re.search(rule.regex, html, re.IGNORECASE))
        else:  # email_headers
            if rule.func:
                hit = bool(rule.func(ctx))
            elif rule.regex:
                # fallback: run regex against concatenated header fields
                headers_joined = " ".join([
                    safe_get(ctx, "from_addr"),
                    safe_get(ctx, "reply_to"),
                    safe_get(ctx, "return_path"),
                    safe_get(ctx, "message_id"),
                ])
                hit = bool(re.search(rule.regex, headers_joined, re.IGNORECASE))

        features[f"match_{rule.rule_id.lower().replace('-', '_')}"] = int(hit)
        if hit:
            reasons.append(f"{rule.rule_id}: {rule.explanation}")

    return features, reasons
