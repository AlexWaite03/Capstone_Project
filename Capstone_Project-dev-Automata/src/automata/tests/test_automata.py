import pytest

# Adjust these imports to match your repo
from automata.nfa import (
    Tok,
    nfa_accepts_tokens,
    build_nfa_url_02_at_in_authority,
)
from automata.dfa import (
    determinize,
    dfa_accepts_text,
    build_counting_dfa,
    build_length_threshold_dfa,
)
from automata.automata_features import (
    extract_features_url,
    extract_features_email,
)

# ----------------------------
# Helpers
# ----------------------------
def feat_key(rule_id: str) -> str:
    return f"match_{rule_id.lower().replace('-', '_')}"


# ============================================================
# 1) Unit tests: NFA correctness (hand-built NFA)
# ============================================================
def test_nfa_url_02_accepts_at_before_slash():
    nfa = build_nfa_url_02_at_in_authority()

    # Note: that NFA example assumes scheme validated externally.
    # We'll only simulate the authority part "abc@def"
    toks = [Tok.LETTER, Tok.LETTER, Tok.LETTER, Tok.AT, Tok.LETTER]
    assert nfa_accepts_tokens(nfa, toks) is True


def test_nfa_url_02_rejects_when_no_at():
    nfa = build_nfa_url_02_at_in_authority()
    toks = [Tok.LETTER, Tok.LETTER, Tok.LETTER, Tok.DOT, Tok.LETTER]
    assert nfa_accepts_tokens(nfa, toks) is False


# ============================================================
# 2) Unit tests: NFA -> DFA equivalence
# ============================================================
def test_dfa_equivalent_to_nfa_for_url_02_demo():
    nfa = build_nfa_url_02_at_in_authority()
    dfa = determinize(nfa, add_sink=True)

    # Again: we're testing the authority substring, not scheme
    # We'll feed raw text and rely on tokenizer in dfa.py
    assert dfa_accepts_text(dfa, "abc@d") is True
    assert dfa_accepts_text(dfa, "abcd") is False


# ============================================================
# 3) Unit tests: counting DFAs
# ============================================================
def test_counting_dfa_dots_threshold():
    # Accept if >= 6 dots
    dfa = build_counting_dfa(Tok.DOT, threshold=6)

    assert dfa_accepts_text(dfa, "a.b.c.d.e.f.g") is True   # 6+ dots
    assert dfa_accepts_text(dfa, "a.b.c") is False          # only 2 dots


def test_length_threshold_dfa():
    dfa = build_length_threshold_dfa(10)  # accept len >= 10 tokens
    assert dfa_accepts_text(dfa, "abcdefghij") is True
    assert dfa_accepts_text(dfa, "abc") is False


# ============================================================
# 4) Integration tests: URL feature extraction
# ============================================================
@pytest.mark.parametrize(
    "url, should_match",
    [
        ("http://192.168.0.10/login", True),
        ("https://example.com/login", False),
    ],
)
def test_url_01_ip_host(url, should_match):
    feats, reasons = extract_features_url(url)
    assert feats[feat_key("URL-01")] == int(should_match)


@pytest.mark.parametrize(
    "url, should_match",
    [
        ("http://paypal.com@evil-site.com/login", True),
        ("https://example.com/path", False),
    ],
)
def test_url_02_at_in_authority(url, should_match):
    feats, reasons = extract_features_url(url)
    assert feats[feat_key("URL-02")] == int(should_match)


def test_url_11_heavy_encoding():
    feats, _ = extract_features_url("https://example.com/%2F%2F%2F%2F%2Flogin")
    assert feats[feat_key("URL-11")] == 1

    feats, _ = extract_features_url("https://example.com/search?q=hello%20world")
    assert feats[feat_key("URL-11")] == 0


def test_url_12_embedded_url():
    feats, _ = extract_features_url("https://example.com/redirect?to=https://evil.com/login")
    assert feats[feat_key("URL-12")] == 1

    feats, _ = extract_features_url("https://example.com/help/http-status-codes")
    assert feats[feat_key("URL-12")] == 0


def test_url_14_shortener():
    feats, _ = extract_features_url("https://bit.ly/3AbCdE")
    assert feats[feat_key("URL-14")] == 1

    feats, _ = extract_features_url("https://example.com/bit.ly/3AbCdE")
    assert feats[feat_key("URL-14")] == 0


# ============================================================
# 5) Integration tests: Email feature extraction
# ============================================================
def test_email_header_mismatch_strong_signal():
    ctx = {
        "from_addr": "Bank Support <support@bank.com>",
        "reply_to": "help@bank-support.net",
        "return_path": "bounce@mailer-suspicious.net",
        "message_id": "<abc123@mailer-suspicious.net>",
        "subject": "Your statement is ready",
        "body_text": "Hello, view your statement.",
        "body_html": "",
        "attachment_names": [],
    }
    feats, reasons = extract_features_email(ctx)
    assert feats[feat_key("EMAIL-02")] == 1
    assert feats[feat_key("EMAIL-03")] == 1
    assert feats[feat_key("EMAIL-06")] == 1


def test_email_otp_is_neutral_not_auto_phish():
    # Legit OTP-style email: should match EMAIL-10 but not urgency/click-here
    ctx = {
        "from_addr": "UWI IT <noreply@uwi.edu>",
        "reply_to": "noreply@uwi.edu",
        "return_path": "noreply@uwi.edu",
        "message_id": "<id@uwi.edu>",
        "subject": "Your OTP code",
        "body_text": "Your verification code is 123456. Do not share this code.",
        "body_html": "",
        "attachment_names": [],
    }
    feats, reasons = extract_features_email(ctx)

    assert feats[feat_key("EMAIL-10")] == 1  # credential words present
    assert feats[feat_key("EMAIL-09")] == 0  # urgency should NOT match
    assert feats[feat_key("EMAIL-11")] == 0  # click here + link should NOT match
    assert feats[feat_key("EMAIL-02")] == 0  # no header mismatch


def test_email_click_here_plus_link():
    ctx = {
        "from_addr": "Support <support@service.com>",
        "reply_to": "support@service.com",
        "return_path": "support@service.com",
        "message_id": "<id@service.com>",
        "subject": "Action needed",
        "body_text": "Click here to verify: https://example.com/verify",
        "body_html": "",
        "attachment_names": [],
    }
    feats, reasons = extract_features_email(ctx)
    assert feats[feat_key("EMAIL-11")] == 1


def test_email_anchor_mismatch_html():
    ctx = {
        "from_addr": "Support <support@service.com>",
        "reply_to": "support@service.com",
        "return_path": "support@service.com",
        "message_id": "<id@service.com>",
        "subject": "Notice",
        "body_text": "See details below.",
        "body_html": '<a href="https://evil.com/login">https://bank.com/login</a>',
        "attachment_names": [],
    }
    feats, reasons = extract_features_email(ctx)
    assert feats[feat_key("EMAIL-14")] == 1


def test_email_risky_attachment():
    ctx = {
        "from_addr": "Billing <billing@company.com>",
        "reply_to": "billing@company.com",
        "return_path": "billing@company.com",
        "message_id": "<id@company.com>",
        "subject": "Invoice attached",
        "body_text": "Please see attached.",
        "body_html": "",
        "attachment_names": ["invoice.exe"],
    }
    feats, reasons = extract_features_email(ctx)
    assert feats[feat_key("EMAIL-15")] == 1
