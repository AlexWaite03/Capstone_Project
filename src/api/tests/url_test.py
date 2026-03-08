from src.automata.automata_features import match_url_01, match_url_02

def test_ip_host_detected():
    url = "http://192.168.0.1/login"
    assert match_url_01(url) is True

def test_normal_domain_not_detected():
    url = "http://example.com"
    assert match_url_01(url) is False

def test_at_in_authority_detected():
    url = "http://user@example.com/login"
    assert match_url_02(url) is True

def test_no_at_in_authority():
    url = "http://example.com/login"
    assert match_url_02(url) is False
