# ============================================================
# Regex Prototype Layer
# Used for validation and experimental pattern matching
# Does NOT replace DFA logic
# ============================================================

import re

# -------------------------
# URL Regex Prototypes
# -------------------------

IP_HOST_REGEX = re.compile(
    r"^https?://\d{1,3}(\.\d{1,3}){3}"
)

AT_IN_AUTHORITY_REGEX = re.compile(
    r"^https?://[^/]*@"
)

LONG_URL_REGEX = re.compile(
    r"^.{120,}$"
)

PUNYCODE_REGEX = re.compile(
    r"^https?://xn--"
)

MULTI_HTTP_REGEX = re.compile(
    r"https?://.*https?://"
)



EXCESSIVE_SPECIAL_SUBJECT_REGEX = re.compile(
    r"[!$#%*]{4,}"
)

ALL_CAPS_SUBJECT_REGEX = re.compile(
    r"^[^a-z]*$"
)

CLICK_HERE_WITH_LINK_REGEX = re.compile(
    r"click here.*https?://",
    re.IGNORECASE
)




def regex_match_ip_host(url: str) -> bool:
    return bool(IP_HOST_REGEX.search(url))


def regex_match_at_authority(url: str) -> bool:
    return bool(AT_IN_AUTHORITY_REGEX.search(url))


def regex_match_long_url(url: str) -> bool:
    return bool(LONG_URL_REGEX.search(url))


def regex_match_click_here(body: str) -> bool:
    return bool(CLICK_HERE_WITH_LINK_REGEX.search(body))
