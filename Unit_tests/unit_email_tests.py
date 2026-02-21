from automata.automata_features import match_email_09

def test_urgency_detected():
    ctx = {
        "subject": "URGENT: Verify Now",
        "body_text": ""
    }
    assert match_email_09(ctx) is True

def test_no_urgency():
    ctx = {
        "subject": "Meeting Reminder",
        "body_text": ""
    }
    assert match_email_09(ctx) is False
