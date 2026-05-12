# CyberLang Analytics — ML Deep Reference Guide
## Capstone Project: Hybrid Phishing Detection System
*For PhD-level examination preparation. Every section is sourced directly from the codebase.*

---

## Table of Contents
1. [System Overview & Philosophy](#1-system-overview--philosophy)
2. [Complete Architecture & Data Flow](#2-complete-architecture--data-flow)
3. [Datasets — Sources, Shape, Preparation](#3-datasets--sources-shape-preparation)
4. [Feature Engineering — Every Feature Explained](#4-feature-engineering--every-feature-explained)
5. [Formal Language Theory — NFA & DFA Engine](#5-formal-language-theory--nfa--dfa-engine)
6. [Automata Rule Library — All 35 Rules](#6-automata-rule-library--all-35-rules)
7. [Machine Learning Models — Training & Configuration](#7-machine-learning-models--training--configuration)
8. [API Infrastructure — How ML Is Served](#8-api-infrastructure--how-ml-is-served)
9. [Testing & Validation — What Guarantees Correctness](#9-testing--validation--what-guarantees-correctness)
10. [Known Limitations & Design Decisions](#10-known-limitations--design-decisions)
11. [PhD-Level Q&A — Anticipated Deep Questions](#11-phd-level-qa--anticipated-deep-questions)

---

## 1. System Overview & Philosophy

**Project name:** CyberLang Analytics  
**Problem being solved:** Phishing detection for URLs and emails  
**Core thesis:** A *hybrid* system outperforms either pure ML or pure rule-based detection alone, by combining the guaranteed-deterministic properties of automata theory with the statistical pattern-learning of machine learning.

### Why "Hybrid"?
- **Pure rules (automata only)** are transparent and explainable but brittle — they can only catch patterns that a human explicitly coded.  
- **Pure ML** is flexible but a black box — it cannot easily explain *why* something is phishing, and it degrades on distributional shift.  
- **Hybrid**: the automata layer produces a structured, interpretable 35-dimensional binary feature vector that the ML model then classifies. This means every prediction carries an audit trail of *which* automata rules fired.

---

## 2. Complete Architecture & Data Flow

```
USER INPUT
    │
    ▼
┌───────────────────────────────────────────────┐
│  Frontend (React / Vite SPA)                  │
│  • URL Scan tab  OR  Email Text Scan tab       │
│  • "How it Works" page describes 3-step flow  │
└───────────────────────┬───────────────────────┘
                        │ HTTP POST
                        ▼
┌───────────────────────────────────────────────┐
│  FastAPI Backend  (src/api/api.py)             │
│                                               │
│  POST /extract_features                        │
│      └─► automata_interface.py                │
│              └─► automata_features.py          │
│                   ├─► extract_features_url()  │  20 URL rules
│                   └─► extract_features_email()│  15 EMAIL rules
│                   Returns: {features, reasons}│
│                                               │
│  POST /predict                                │
│      └─► joblib.load(phishing_model.joblib)   │
│              └─► model.predict([24 features]) │
│                                               │
│  POST /detect  (alias for extract_features)   │
│  GET  /health                                 │
└───────────────────────────────────────────────┘

OFFLINE TRAINING PIPELINE (Jupyter Notebooks)
    data_prep_01.ipynb
        → PhishTank URLs + Tranco benign URLs
        → final_phishing_dataset.csv  (≈40k rows, label 0/1)
    feature_extraction.ipynb
        → lexical features (7) + automata rules (20) per URL
        → hybrid_dataset.csv
    model_training.ipynb
        → RandomForestClassifier (100 trees)
        → phishing_model.joblib  ← loaded by API at startup
    train_email_model.ipynb
        → TF-IDF (5000 features) + RandomForestClassifier
        → email_model.joblib + tfidf_vectorizer.joblib
```

---

## 3. Datasets — Sources, Shape, Preparation

### 3.1 URL Dataset

| Source | File | Label | Size used |
|--------|------|-------|-----------|
| **PhishTank** (crowdsourced verified phishing) | `data/raw/verified_online.csv` | 1 (phishing) | 20,000 rows sampled randomly |
| **Tranco Top-1M** (Alexa-successor; popularity-ranked benign domains) | `data/raw/trancoList.csv` | 0 (legitimate) | 20,000 rows (top-ranked) |

**Preparation steps** (`data_prep_01.ipynb`):
1. Load PhishTank CSV — keep only `url` column, assign `label=1`
2. Load Tranco CSV (no header: columns `rank, domain`) — prepend `"http://"` to each domain, assign `label=0`
3. Concatenate → shuffle (`random_state=42`) → drop duplicates on `url`
4. Save as `final_phishing_dataset.csv` (~40k rows, balanced 50/50)

**Why balanced?** An imbalanced dataset would bias the model toward the majority class. 50/50 ensures accuracy is a meaningful metric and prevents trivial over-prediction.

**Why Tranco and not a random crawl?** Tranco lists the most-visited legitimate domains — they represent real-world benign traffic, making the boundary between classes harder and more representative.

### 3.2 Email Dataset

| Source | File | Labels | Feature used |
|--------|------|--------|-------------|
| **Kaggle** phishing email dataset | `data/raw/phishing_email.csv` | 0=Safe, 1=Phishing | `text_combined` (subject + body concatenated) |

**Preparation** (`email_exploration.ipynb` + `train_email_model.ipynb`):
- Drop rows where `text_combined` is NaN
- No separate feature engineering — raw text → TF-IDF directly

---

## 4. Feature Engineering — Every Feature Explained

### 4.1 Lexical Features (7 features, URL only)

These are simple character-level statistics computed in `feature_extraction.ipynb`:

| Feature | Computation | Phishing signal |
|---------|------------|-----------------|
| `url_len` | `len(url)` | Phishing URLs tend to be longer (obfuscation, added path segments) |
| `n_dots` | `url.count('.')` | Deep subdomain nesting adds dots |
| `n_hyphens` | `url.count('-')` | Brand impersonation: `pay-pal-secure.com` |
| `n_digits` | `sum(c.isdigit() for c in url)` | Auto-generated phishing URLs have random digits |
| `n_slashes` | `url.count('/')` | Long paths with many redirects |
| `has_sus_kw` | binary: any of `['login','secure','account','update','banking','verify']` in url.lower() | Credential-harvesting page patterns |
| `has_https` | binary: `"https" in url` | Paradoxically, phishing sites increasingly *do* use HTTPS, making this a weak feature |

**Critical insight found during training:** `url_len`, `n_slashes`, and `has_https` were identified as "cheat" features — they correlate with phishing in the training data but not for the right reasons (e.g., all PhishTank URLs are full paths while Tranco entries are just domains). The final production model therefore uses a **"Hard Mode"** feature set that *removes* these three features, leaving 4 lexical + 20 automata = **24 features total**.

### 4.2 Automata Features (20 URL + 15 Email = 35 features)

Computed by the automata engine (see Section 6). Each is a binary 0/1 value. Feature names are formatted as `match_url_01` through `match_url_20` and `match_email_01` through `match_email_15`.

### 4.3 TF-IDF Features (Email model only)

- Vocabulary: top 5,000 words by term frequency across the training corpus
- Stop words: English stop words removed (the, and, is, etc.)
- Each email becomes a sparse 5,000-dimensional vector
- Values: TF-IDF weight = term frequency × inverse document frequency
- **TF-IDF formula:** `tf(t,d) × log(N/df(t))` — words that appear frequently in one email but rarely across all emails get high weight

**Why TF-IDF over word embeddings?** It is fast, interpretable (most-weighted words can be inspected directly), and works well for bag-of-words classification tasks where word order matters less than vocabulary.

---

## 5. Formal Language Theory — NFA & DFA Engine

This is the theoretical core of the project, linking computer science theory (COMP 2605 / Theory of Computation) to practical security.

### 5.1 Token Alphabet (`src/automata/nfa.py`)

Rather than operating on raw characters, the system maps every character to one of 13 character *classes* (tokens). This **abstracts** the input, making the automata smaller and more general:

```
Tok.DIGIT     → [0-9]
Tok.LETTER    → [a-zA-Z]
Tok.DOT       → .
Tok.SLASH     → /
Tok.AT        → @
Tok.HYPHEN    → -
Tok.PERCENT   → %
Tok.EQUAL     → =
Tok.AMP       → &
Tok.QMARK     → ?
Tok.COLON     → :
Tok.UNDERSCORE→ _
Tok.OTHER     → everything else
```

**Why tokenize?** A character-level DFA for "URL length ≥ 120" would require 120 states, one per character — but the counting DFA only needs `threshold+1` states when operating on abstract tokens (since every token advances the length counter by 1 regardless of what it is). Tokenization also makes the NFA/DFA smaller and the subset construction cheaper.

### 5.2 NFA Structure (`src/automata/nfa.py`)

```python
@dataclass
class NFA:
    start: State          # integer
    accepts: Set[State]   # set of accepting states
    trans: Dict[Tuple[State, Tok], Set[State]]  # non-deterministic transitions
    eps: Dict[State, Set[State]]                # ε-transitions
```

**Core algorithms:**
- `eps_closure(nfa, states)` — computes the set of all states reachable from a set via ε-transitions (stack-based BFS/DFS). This is required before every move.
- `move(nfa, states, tok)` — returns all states reachable from a set of states on a given token.
- `nfa_accepts_tokens(nfa, toks)` — simulates the NFA: starts at `eps_closure({start})`, applies `move` + `eps_closure` for each token, accepts if final set intersects accept states.

**Builder API (`NFABuilder`)** — Thompson-construction style fragment building:
- `literal(tok)` → fragment matching exactly one token
- `concat(a, b)` → fragment matching `a` then `b`
- `union(a, b)` → fragment matching `a` or `b` (new start with ε to both)
- `star(a)` → Kleene star (ε-back-loop to allow repetition)
- `optional(a)` → `a?` (union with ε fragment)
- `finalize(frag)` → converts fragment to complete NFA by adding a single accept state

**Hand-built example:** `build_nfa_url_02_at_in_authority()` — a 2-state NFA that accepts any token stream containing at least one `AT` token (to detect `@` in a URL's authority section). It uses a loop on both states and a transition from state 0 to state 1 on `Tok.AT`.

### 5.3 DFA Structure and Subset Construction (`src/automata/dfa.py`)

```python
DState = FrozenSet[int]   # a DFA state is a FROZENSET of NFA states

@dataclass
class DFA:
    start: DState
    accepts: Set[DState]
    trans: Dict[Tuple[DState, Tok], DState]  # deterministic: exactly one next state
    sink: Optional[DState]                   # explicit dead state for total transitions
```

**`determinize(nfa)` — Subset Construction algorithm:**
1. Start state = `eps_closure({nfa.start})`
2. For each unmarked DFA state S and each token tok:
   - Compute `U = eps_closure(move(S, tok))`
   - Add transition `(S, tok) → U`
   - If U is new, mark it for processing
3. A DFA state is accepting iff any of its constituent NFA states is accepting
4. If `add_sink=True`, add explicit dead-state transitions for missing entries (makes the transition function *total*)

**Complexity:** Subset construction is O(2^n) states in the worst case for an n-state NFA, but in practice the rule NFAs are small (2–5 states) so this is negligible.

**`minimize_dfa(dfa)` — Hopcroft's algorithm:**
1. Initial partition: accepting states vs. non-accepting states
2. Iteratively refine partitions: if two states in the same partition go to different partitions on some token, split them
3. Replace each equivalence class with a single representative state
4. Produces the **minimum-state DFA** for the language

**Why minimize?** Smaller DFAs are faster to simulate and use less memory. More importantly, it proves you haven't introduced redundant states.

### 5.4 Counting DFAs (hand-built, no NFA needed)

For threshold rules that just count token occurrences, `build_counting_dfa(trigger_tok, threshold)` constructs a DFA directly:
- States: `{0, 1, 2, ..., threshold}` (as frozensets)
- On `trigger_tok`: advance count (saturate at `threshold`)
- On any other token: stay at current count
- Accept state: `{threshold}` only
- Example: `_DFA_URL_MANY_DOTS = build_counting_dfa(Tok.DOT, threshold=6)` — accepts iff ≥6 dots

Similarly, `build_length_threshold_dfa(threshold)`:
- Every token (regardless of type) advances the counter
- Accepts iff stream length ≥ threshold
- Example: `_DFA_URL_VERY_LONG = build_length_threshold_dfa(120)`

**Pre-built DFAs instantiated at module load:**
```python
_DFA_URL_MANY_DOTS = build_counting_dfa(Tok.DOT, threshold=6)   # URL-18
_DFA_URL_VERY_LONG = build_length_threshold_dfa(120)             # URL-05
```

---

## 6. Automata Rule Library — All 35 Rules

### 6.1 URL Rules (20)

Each rule function takes a URL string and returns a boolean. Each maps directly to a well-known phishing indicator from security literature.

| Rule ID | Name | Mechanism | Severity | Security Rationale |
|---------|------|-----------|----------|--------------------|
| URL-01 | IP address as host | Structural: parse host, split on `.`, check 4 parts all-digit | 2 | Phishers use raw IPs to avoid domain registration costs and WHOIS exposure |
| URL-02 | `@` in authority | NFA / string scan | 3 | `http://paypal.com@evil.com/` — browser ignores everything before `@` |
| URL-03 | Deep subdomain (≥4 dots in host) | Count dots in extracted host | 2 | `paypal.com.signin.verify.evil.com` tricks visual inspection |
| URL-04 | Hyphen-heavy host (≥3 hyphens) | Count hyphens in host | 2 | `pay-pal-secure-login.com` mimics brand names |
| URL-05 | Very long URL (≥120 chars) | Length threshold DFA | 1 | Long URLs hide the real destination and add confusion |
| URL-06 | Credential keywords in path/query | Keyword scan on `/path` and `?param=` | 2 | `/login`, `/verify`, `?password=` signal credential-harvesting pages |
| URL-07 | Brand keyword + suspicious TLD | Combined lookup | 2 | `paypal.tk`, `netflix.ml` — typosquatting on free-registration TLDs |
| URL-08 | Suspicious TLD | Lookup in `{tk, ml, ga, cf, gq}` | 1 | These TLDs offer free registration and have extremely high abuse rates |
| URL-09 | High digit ratio (>0.25) | `digits / len(url) > 0.25` | 1 | Auto-generated phishing URLs: `a1b2c3d4e5f6.com/xyz123` |
| URL-10 | Many special chars (≥12) | Count of `-_%=&` | 1 | Obfuscation and query string manipulation |
| URL-11 | Heavy URL encoding (≥5 `%xx`) | Deterministic scan counting `%XX` patterns | 2 | `%2F%2F` encodes `//`, used to hide directory traversal or redirect targets |
| URL-12 | Embedded second URL | Find second `http://` in string | 2 | `https://good.com/redirect?to=https://evil.com` |
| URL-13 | Redirect parameter with URL | Detect `?url=`, `?redirect=`, `?next=` etc. + embedded URL | 2 | Open redirectors on legitimate domains used as launchers |
| URL-14 | Known shortener domain | Prefix match against `{bit.ly, tinyurl.com, t.co, is.gd, cutt.ly}` | 1 | Shorteners hide final destination; commonly used in phishing campaigns |
| URL-15 | Dangerous file extension | String search for `.exe`, `.scr`, `.js`, `.jar`, `.bat`, `.ps1`, `.vbs` | 3 | Direct malware delivery via URL |
| URL-16 | Punycode domain (`xn--`) | Prefix match | 2 | Homograph attacks: `xn--pple-43d.com` renders as `аpple.com` in browser |
| URL-17 | Odd separators / repeated slashes | Regex `//[^/]+//` or `/(\\|;){2,}` | 1 | Path traversal and parser confusion attacks |
| URL-18 | Many dots overall (≥6) | Counting DFA | 1 | Combines deep subdomain + multiple path segments in obfuscated URLs |
| URL-19 | Suspicious words in host | String search for `secure`, `account`, `verify` in extracted host | 1 | `secure-banking.evil.com` uses trust-building vocabulary in the domain |
| URL-20 | Repeated credential segments | Find second occurrence of `/login`, `/verify`, `/account` | 1 | `/account/login/verify/account` is structurally abnormal |

### 6.2 Email Rules (15)

Each rule takes an `email_ctx` dictionary with keys: `from_addr`, `reply_to`, `return_path`, `message_id`, `subject`, `body_text`, `body_html`, `attachment_names`, `display_name`.

| Rule ID | Name | Signal Type | Severity | Security Rationale |
|---------|------|-------------|----------|--------------------|
| EMAIL-01 | Invalid From format | Regex: `[a-z0-9._%+-]+@domain.tld` | 1 | Malformed From headers bypass naive filters |
| EMAIL-02 | From ≠ Reply-To domain | Domain extraction + comparison | 3 | Attacker shows legit From but captures replies at their domain |
| EMAIL-03 | From ≠ Return-Path domain | Domain extraction + comparison | 3 | Bounce messages go to attacker's server — reveals true origin |
| EMAIL-04 | Reply-To missing | Presence check | 1 | Bulk phishing tools often omit standard headers |
| EMAIL-05 | Return-Path missing | Presence check | 1 | Same as above |
| EMAIL-06 | From ≠ Message-ID domain | Domain extraction + comparison | 2 | Message-ID is auto-generated from sending server; mismatch reveals spoofing |
| EMAIL-07 | Excessive special chars in subject | Regex `[!$#%*]{4,}` | 1 | `!!!URGENT!!! $$$ VERIFY NOW $$$` — attention-grabbing noise |
| EMAIL-08 | Subject mostly ALL CAPS (>85%) | Count uppercase letters / total letters > 0.85 | 1 | ALL CAPS is a documented pressure tactic in phishing |
| EMAIL-09 | Urgency language | Keyword scan: `urgent, immediately, act now, final notice, suspended, locked, verify now, action required` | 1 | Social engineering — manufactured urgency bypasses rational evaluation |
| EMAIL-10 | Credential words (neutral) | Keyword scan: `password, pin, one-time, otp, security code, verification code` | 1 | Neutral because legitimate OTP emails also contain these words — must combine with other signals |
| EMAIL-11 | "Click here" + link | "click here" in body AND regex URL present | 1 | Classic phishing call-to-action pattern |
| EMAIL-12 | Display-name brand mismatch | Display name contains brand word not found in from domain | 2 | `"PayPal Support" <attacker@random.com>` — visual trust but technical mismatch |
| EMAIL-13 | Many links in body (≥5) | Count regex `https?://\S+` matches | 1 | Phishing campaigns sometimes embed many redirect links |
| EMAIL-14 | Anchor text URL mismatch (HTML) | Parse `<a href="X">Y</a>`, check if Y looks like URL but differs from X | 2 | `<a href="evil.com">bank.com</a>` — the displayed URL is not the real destination |
| EMAIL-15 | Risky attachment extension | Check `attachment_names` list for `.exe,.js,.vbs,.scr,.bat,.ps1,.jar` | 3 | Malware delivery via email attachment |

### 6.3 Severity Scoring

Rules are tagged with severity 1 (weak), 2 (medium), or 3 (strong). Severity 3 rules (URL-02, URL-15, EMAIL-02, EMAIL-03, EMAIL-15) are individually strong phishing indicators. Severity 1 rules are only meaningful in combination.

### 6.4 The OTP-Safe Logic

A specific edge-case handler `otp_safe_summary()` in `automata_features.py` prevents legitimate 2FA/OTP emails from being falsely flagged:

```
EMAIL-10 fires (credential words) + 
NO (EMAIL-02 OR EMAIL-03 OR EMAIL-06) + 
NO EMAIL-09 + 
NO EMAIL-11
→ "OTP/login wording detected (neutral). No strong mismatch, urgency, or suspicious link signals."
```

This is grounded in the understanding that `password / verification code / otp` are vocabulary that appears in *both* phishing emails *and* legitimate service notifications.

---

## 7. Machine Learning Models — Training & Configuration

### 7.1 URL Phishing Model (`phishing_model.joblib`)

**Algorithm:** `RandomForestClassifier` from scikit-learn  
**Configuration:** `n_estimators=100, random_state=42`  
**Framework:** scikit-learn 1.7.2  
**Serialization:** `joblib.dump` / `joblib.load`

#### Feature Sets Compared During Development

| Model Variant | Features | Count | Purpose |
|--------------|----------|-------|---------|
| Baseline | url_len, n_dots, n_hyphens, n_digits, n_slashes, has_sus_kw, has_https | 7 | Naive lexical-only model |
| Hybrid | Baseline + all 20 automata URL features | 27 | First hybrid test |
| Hard Baseline | n_dots, n_hyphens, n_digits, has_sus_kw | 4 | Baseline with "cheat" features removed |
| **Hard Hybrid (Production)** | Hard Baseline + 20 automata URL features | **24** | Final model saved to disk |

The "cheat" feature discovery was a critical analytical step: `url_len`, `n_slashes`, and `has_https` all correlate artificially with labels in the dataset (PhishTank URLs are full paths, Tranco entries are bare domains) but would not generalize to real-world inputs where legitimate URLs can also be long with many slashes.

#### Training Pipeline
```python
# data split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# train
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train[hard_hybrid_features], y_train)

# evaluate
classification_report(y_test, model.predict(X_test[hard_hybrid_features]))
# → precision, recall, F1-score for both classes

# save
joblib.dump(model, '../data/processed/phishing_model.joblib')
```

**Data split:** 80% train / 20% test. `random_state=42` ensures reproducibility.

#### Why Random Forest?
- Handles both binary (automata rule hits) and continuous (count features) inputs without scaling
- Naturally produces feature importances via mean impurity decrease (Gini importance), which the team used to diagnose the "cheat" features
- Resistant to overfitting relative to a single decision tree due to bagging and random feature subsets at each split
- `n_estimators=100` is a standard baseline — 100 trees provides good variance reduction

### 7.2 Email Classification Model (`email_model.joblib`)

**Algorithm:** `RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)`  
**Feature extraction:** `TfidfVectorizer(max_features=5000, stop_words='english')`  
**Input:** Raw email text (`text_combined` column — subject + body concatenated)  
**Serialization:** Both model and vectorizer saved separately

#### Training Pipeline
```python
# text → TF-IDF matrix
vectorizer = TfidfVectorizer(max_features=5000, stop_words='english')
X = vectorizer.fit_transform(df['text_combined'])   # sparse matrix, shape (n_emails, 5000)
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

email_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
email_model.fit(X_train, y_train)

# save BOTH artifacts — needed together at inference time
joblib.dump(email_model, 'data/processed/email_model.joblib')
joblib.dump(vectorizer, 'data/processed/tfidf_vectorizer.joblib')
```

`n_jobs=-1` uses all available CPU cores during training (parallel tree construction).

**Why save the vectorizer separately?** At inference time, text must be transformed using the *same* vocabulary and IDF weights learned on training data. Re-fitting the vectorizer on new data would produce a completely different feature space that the model was never trained on.

#### TF-IDF Deep Dive
- **Term Frequency (TF):** Raw count of word `t` in document `d`, normalized by document length
- **Inverse Document Frequency (IDF):** `log(1 + N / (1 + df(t)))` where N = total documents, df(t) = documents containing term t
- **Result:** Common phishing vocabulary (`verify`, `suspended`, `account`, `password`) gets high IDF weight when it appears in few legitimate emails
- **`max_features=5000`:** Only the 5000 highest-TF terms across the corpus are kept, discarding very rare noise terms
- **`stop_words='english'`:** Articles, prepositions, conjunctions removed — they don't carry semantic signal for classification

### 7.3 Model Evaluation Metrics Used

The `classification_report` from scikit-learn was used, providing:

| Metric | Formula | Why it matters for phishing detection |
|--------|---------|---------------------------------------|
| **Precision** | TP / (TP + FP) | Low precision → many false alarms (legitimate emails flagged) |
| **Recall** | TP / (TP + FN) | Low recall → missed phishing emails (dangerous for security) |
| **F1-Score** | 2×(P×R)/(P+R) | Harmonic mean — balanced when classes matter equally |
| **Accuracy** | (TP+TN)/(Total) | Meaningful here only because dataset is balanced (50/50) |
| **Confusion Matrix** | [[TN,FP],[FN,TP]] | Visualized with seaborn heatmap to diagnose error types |

**Important:** On an imbalanced dataset, accuracy alone is misleading. The balanced dataset was intentional to make accuracy a valid single-number summary.

---

## 8. API Infrastructure — How ML Is Served

### 8.1 FastAPI Application (`src/api/api.py`)

```
uvicorn src.api.api:app --reload
```

The ML model is loaded **once at module import time**:
```python
model = joblib.load("data/processed/phishing_model.joblib")
```

This means the model is kept in memory for the lifetime of the process — no per-request disk I/O.

### 8.2 Endpoints

#### `POST /extract_features`
**Purpose:** Run the automata pipeline, return structured feature vector + human-readable reasons  
**Input:**
```json
{
  "url": "http://192.168.0.1/login",
  "email_ctx": {
    "from_addr": "support@bank.com",
    "reply_to": "help@attacker.net",
    "subject": "URGENT: Account suspended",
    "body_text": "Click here to verify..."
  }
}
```
**Output:**
```json
{
  "features": {"match_url_01": 1, "match_url_06": 1, ...},
  "matched_rules": ["URL-01", "URL-06", "EMAIL-02", "EMAIL-09"],
  "reasons": ["URL-01: IP address used as host", "EMAIL-09: Urgency/pressure language"]
}
```

#### `POST /detect`
Same as `/extract_features` — alias that passes through to `automata_interface`.

#### `POST /predict`
**Purpose:** Run the saved ML model and return phishing/legitimate prediction  
**Input:** Either a pre-computed `features: [24 floats]` or `url`/`email_ctx` to auto-extract  
**Validation:** Exactly 24 features required (matches the hard hybrid feature count)  
**Output:** `{"prediction": 0}` (legitimate) or `{"prediction": 1}` (phishing)

#### `GET /health`
Returns `{"status": "ok", "message": "API is running"}`

### 8.3 Interface Chain (`src/api/automata_interface.py`)

```
automata_interface(url, email_ctx)
    → extract_automata_features(url, email_ctx)  # from automata_features.py
        → extract_features_url(url)              # returns (dict, reasons)
        → extract_features_email(email_ctx)      # returns (dict, reasons)
    → extract rule IDs from reasons
    → return { features, matched_rules, reasons }
```

### 8.4 Data Validation (`pydantic`)

All request bodies are validated via Pydantic models:
- `EmailContext` — enforces type and optional fields
- `FeatureRequest` — `url` and `email_ctx` both optional (but one must be provided)
- `PredictRequest` — `features: List[float]`
- `DetectionRequest` — flexible for detect endpoint

---

## 9. Testing & Validation — What Guarantees Correctness

Testing is configured via `pytest.ini`:
```ini
[pytest]
testpaths = src/automata/tests  src/api/tests
pythonpath = .
addopts = -v
```

### 9.1 Automata Unit Tests (`src/automata/tests/test_automata.py`)

#### Layer 1: NFA Correctness
```python
test_nfa_url_02_accepts_at_before_slash()
    → tokens [LETTER, LETTER, LETTER, AT, LETTER] → True ✓

test_nfa_url_02_rejects_when_no_at()
    → tokens [LETTER, LETTER, LETTER, DOT, LETTER] → False ✓
```
These verify the hand-built NFA for URL-02 is mathematically correct.

#### Layer 2: NFA → DFA Equivalence (Subset Construction)
```python
test_dfa_equivalent_to_nfa_for_url_02_demo()
    → dfa_accepts_text(dfa, "abc@d") == True   ✓
    → dfa_accepts_text(dfa, "abcd")  == False  ✓
```
This verifies that `determinize()` produces an equivalent DFA — the DFA accepts exactly the same strings as the NFA.

#### Layer 3: Counting DFA Correctness
```python
test_counting_dfa_dots_threshold()
    → dfa_accepts_text(dfa, "a.b.c.d.e.f.g") == True   # 6 dots ✓
    → dfa_accepts_text(dfa, "a.b.c")          == False  # 2 dots ✓

test_length_threshold_dfa()
    → dfa_accepts_text(dfa, "abcdefghij") == True   # 10 chars ✓
    → dfa_accepts_text(dfa, "abc")         == False  # 3 chars ✓
```

#### Layer 4: URL Rule Integration Tests (parametrized)
```python
@pytest.mark.parametrize("url, should_match", [
    ("http://192.168.0.10/login", True),   # IP host → True
    ("https://example.com/login", False),   # domain host → False
])
def test_url_01_ip_host(url, should_match):
    feats, _ = extract_features_url(url)
    assert feats["match_url_01"] == int(should_match)
```

URL-11 (heavy encoding), URL-12 (embedded URL), URL-14 (shortener) all have equivalent parametrized tests.

#### Layer 5: Email Rule Integration Tests

| Test | What it validates |
|------|------------------|
| `test_email_header_mismatch_strong_signal` | EMAIL-02, EMAIL-03, EMAIL-06 all fire simultaneously when From/Reply-To/Return-Path/Message-ID domains all mismatch |
| `test_email_otp_is_neutral_not_auto_phish` | EMAIL-10 fires but EMAIL-09, EMAIL-11, EMAIL-02 do NOT — proving OTP emails are not auto-flagged |
| `test_email_click_here_plus_link` | EMAIL-11 fires on "Click here to verify: https://example.com/verify" |
| `test_email_anchor_mismatch_html` | EMAIL-14 fires on `<a href="evil.com">https://bank.com/login</a>` |
| `test_email_risky_attachment` | EMAIL-15 fires on `attachment_names=["invoice.exe"]` |

### 9.2 API Integration Tests (`src/api/tests/api_test.py`)

Tests use FastAPI's `TestClient` (which runs the app in-process — no network needed):
```python
client = TestClient(app)

test_extract_features_ip_url()
    → POST /extract_features with http://192.168.0.1/login
    → status 200, features["match_url_01"] == 1, "URL-01" in matched_rules ✓

test_extract_features_normal_url()
    → POST /extract_features with http://example.com
    → features["match_url_01"] == 0 ✓

test_email_invalid_from()
    → POST /extract_features with from_addr="invalidemail"
    → features["match_email_01"] == 1 ✓
```

### 9.3 Component-level Tests

`url_test.py` — directly tests `match_url_01`, `match_url_02` imported from `automata_features`  
`email_test.py` — directly tests `match_email_09` (urgency detection)

### 9.4 Regex Prototype Layer (`src/api/regex_prototype.py`)

A separate set of compiled regex patterns (`IP_HOST_REGEX`, `AT_IN_AUTHORITY_REGEX`, `LONG_URL_REGEX`, `PUNYCODE_REGEX`, `MULTI_HTTP_REGEX`) exists as an experimental/validation layer. These are **not** used in the production pipeline — they are reference implementations to verify the automata rules produce equivalent results. This separation is architecturally important: it means the system can be audited by comparing automata outputs against independently written regex.

---

## 10. Known Limitations & Design Decisions

### 10.1 EMAIL-12 Is a Stub
`match_email_12` (display-name brand mismatch) always returns `False` in `patterns.py`:
```python
func=lambda ctx: False
```
The full implementation exists in `automata_features.py` and checks if display name contains a brand word not in the From domain. The patterns.py version was marked as "implement later."

### 10.2 The `/predict` Endpoint Has a Bug
In `api.py`, the predict endpoint tries to extract features as `features_dict[f"feat{i}"]` when auto-extracting, but `automata_interface` returns keys like `match_url_01` — not `feat1`, `feat2`, etc. This code path would raise a `KeyError`. The manual `features: List[float]` path works correctly.

### 10.3 No HTTPS Context for the Email Model
The email model (TF-IDF + RF) is trained on raw text and has no integration with the automata pipeline's header mismatch detection. The two email analysis systems (text-based TF-IDF and header-based automata) currently run independently.

### 10.4 Balanced Dataset Trade-off
The 50/50 class balance was chosen for training simplicity but is unrealistic — in the real world, the vast majority of emails/URLs are legitimate. A production system would need to account for class imbalance using techniques like `class_weight='balanced'` or SMOTE, and would monitor precision/recall separately rather than relying on accuracy.

### 10.5 No Cross-Validation
The evaluation uses a single 80/20 split. For a more rigorous assessment, k-fold cross-validation (`sklearn.model_selection.cross_val_score`) would provide confidence intervals on metrics.

### 10.6 Suspicious TLD List Is Static
`SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq"}` is hardcoded. In production, this should be sourced from a regularly-updated threat intelligence feed (e.g., Spamhaus DBL, OpenPhish).

---

## 11. PhD-Level Q&A — Anticipated Deep Questions

### Theory of Computation

**Q: Why use formal automata at all when you have machine learning?**  
A: Automata provide *formal guarantees* that a pure ML system cannot. A DFA either accepts or rejects a string — there is no probability, no ambiguity, and no possibility of the model "forgetting" a rule because it was underrepresented in training data. The automata layer also provides interpretability: you can prove mathematically that if a URL contains `@` before the first `/`, the URL-02 rule fires, regardless of training distribution. ML handles the subtle patterns that cannot be enumerated by rules.

**Q: Prove that your NFA and DFA recognize the same language.**  
A: The `determinize()` function implements the standard subset construction theorem. The theorem (Rabin-Scott 1959) states that for every NFA M, there exists a DFA M' such that L(M) = L(M'). The proof is by construction: each DFA state represents a subset of NFA states, and by induction, after reading any string w, the DFA is in state S iff the NFA has precisely S as its active state set. The test `test_dfa_equivalent_to_nfa_for_url_02_demo` empirically validates equivalence on the URL-02 hand-built NFA.

**Q: What is the time complexity of your automata pipeline?**  
A: Tokenization is O(|url|). DFA simulation is O(|url|) — one state lookup per token, each lookup O(1) in the dict. Subset construction is O(2^n × |Σ|) where n = NFA states and |Σ| = 13 tokens, but our NFAs are small (2–4 states), so in practice this is O(1) relative to input size. The overall feature extraction for one URL is O(35 × |url|).

**Q: Are all 35 rules recognizing regular languages?**  
A: Mostly yes, with two exceptions. URL-09 (digit *ratio* > 0.25) requires division — a ratio cannot be expressed as a pure DFA over the token alphabet without encoding rational arithmetic, so it's implemented as a numeric post-processing step. EMAIL-14 (anchor text mismatch in HTML) requires parsing HTML structure, which is technically context-free, not regular. All other rules are regular and could in principle be represented as pure DFAs.

**Q: Why tokenize into character classes rather than operating on raw characters?**  
A: For two reasons: (1) abstraction reduces the state count — a counting DFA for "≥6 dots" over character classes needs only 7 states, vs. 7 states per character class in a raw-character DFA (same number here, but the transitions are much sparser); (2) generalization — the NFA for URL-02 matches `@` regardless of what alphabetic characters appear in the username, which is the desired behaviour.

### Machine Learning

**Q: Why Random Forest and not SVM, logistic regression, or a neural network?**  
A: For this feature set (binary 0/1 automata flags + small integer counts), Random Forest has practical advantages: it handles mixed binary/continuous features without scaling, it produces feature importances that diagnose problems (which is how the "cheat" features were found), it is resistant to overfitting with 100 trees, and it is fast to train and infer on a 24-dimensional feature space. SVMs would require kernel selection and scaling. A neural network would be gross overkill for 24 features and ~40k samples, and would sacrifice interpretability.

**Q: How did you identify and address data leakage?**  
A: The team discovered that `url_len`, `n_slashes`, and `has_https` were inflated by a *dataset artifact*: PhishTank provides full URL paths while Tranco provides bare domain names. These features correlate with the label in training but the correlation is due to data collection methodology, not phishing behaviour. The solution was to remove these features from the final model (the "Hard Mode" experiment) and demonstrate that the hybrid model maintained performance using only pattern-based features.

**Q: With a balanced 50/50 dataset, your accuracy is interpretable — but what would happen with real-world class imbalance?**  
A: In production, legitimate traffic might be 99%+ of all inputs. A model trained on 50/50 data applied to 99/1 data would see its false positive rate dominate. The correct approach would be: (1) train with `class_weight='balanced'` or oversample the minority class; (2) evaluate on precision-recall curve rather than ROC; (3) select a probability threshold that minimizes user-facing false positives while keeping recall high for the phishing class.

**Q: What is the feature importance of the automata features relative to the lexical features?**  
A: The team explicitly computed `base_model.feature_importances_` on the baseline model (visualized with a seaborn barplot). The key finding was that size-correlated features dominated the baseline. In the hybrid model, the automata features (particularly the structural mismatch and credential keyword rules) provide additional discriminative power that is not reducible to URL length.

**Q: How does the TF-IDF email model complement the automata email features?**  
A: They operate on different representations of the same input. The automata model checks *structural* signals: header mismatches, presence of urgency phrases, HTML anchor mismatches — things a human security analyst would look for. The TF-IDF model learns *distributional* signals: what vocabulary combinations statistically separate phishing from legitimate email in the training corpus. They could be combined into a late-fusion ensemble, but in the current implementation they are separate inference paths.

**Q: Why `n_estimators=100` and not tuned via cross-validation?**  
A: This is a documented limitation. 100 trees is a widely-cited practical default for Random Forests. A rigorous approach would use `GridSearchCV` or `RandomizedSearchCV` over hyperparameters including `n_estimators`, `max_depth`, `min_samples_split`, and `max_features`, evaluated via k-fold cross-validation. For a capstone project with a balanced medium-sized dataset, 100 trees is sufficient to demonstrate the concept.

### Software Engineering

**Q: How does the API ensure the feature vector is aligned at inference time?**  
A: The API's `/predict` endpoint enforces `len(features) == 24`. The feature extraction pipeline (`automata_features.py`) always produces features in a fixed, deterministic order: URL-01 through URL-20, then EMAIL-01 through EMAIL-15. The URL model uses only the 24 hard-hybrid features (4 lexical + 20 URL automata). Since feature ordering is determined by the `URL_RULES` and `EMAIL_RULES` lists (which are fixed), inference is reproducible.

**Q: How is the model versioned and how would you deploy updates?**  
A: Currently, the model is loaded from a static path (`data/processed/phishing_model.joblib`). In production, this would require a model registry (e.g., MLflow, DVC) with versioned artifacts, an A/B testing framework to compare new models against the incumbent, and canary deployment. The current setup is appropriate for a prototype/capstone environment.

**Q: Why FastAPI over Flask?**  
A: FastAPI provides automatic OpenAPI/Swagger documentation (accessible at `/docs`), built-in Pydantic request validation, async support (though not used here), and better type annotations throughout. For a capstone demo, the automatic Swagger UI at `/docs` is particularly valuable for showing live API interaction.

---

## Appendix A: Full Technology Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| Backend API | FastAPI + Uvicorn | 0.128.0 |
| ML framework | scikit-learn | 1.7.2 |
| Model serialization | joblib | 1.5.3 |
| Data manipulation | pandas | 2.3.3 |
| Numerical computation | numpy | 2.2.6 |
| Data validation | pydantic | 2.12.5 |
| Testing | pytest | 9.0.2 |
| Frontend | React + Vite | — |
| Dashboard (optional) | Streamlit | 1.53.1 |
| Python | CPython | 3.x |

---

## Appendix B: File-to-Concept Map

| File | What it is |
|------|-----------|
| `src/automata/nfa.py` | NFA data structure, ε-closure, move, NFABuilder, hand-built NFA example |
| `src/automata/dfa.py` | DFA data structure, subset construction, Hopcroft minimization, counting/length DFAs |
| `src/automata/automata_features.py` | All 35 rule implementations, `extract_features_url`, `extract_features_email`, OTP-safe logic |
| `src/automata/patterns.py` | Alternative PatternRule registry with regex + func per rule (validation layer) |
| `src/api/automata_interface.py` | Thin wrapper connecting automata pipeline to the API |
| `src/api/api.py` | FastAPI app: `/extract_features`, `/predict`, `/detect`, `/health` |
| `src/api/regex_prototype.py` | Independently-written regexes to cross-validate automata rule outputs |
| `src/automata/tests/test_automata.py` | Full unit + integration test suite for NFA, DFA, all rules |
| `src/api/tests/api_test.py` | API endpoint integration tests via TestClient |
| `src/api/tests/url_test.py` | Direct unit tests of URL-01, URL-02 rule functions |
| `src/api/tests/email_test.py` | Direct unit test of EMAIL-09 urgency detection |
| `notebooks/data_prep_01.ipynb` | Dataset assembly: PhishTank + Tranco → `final_phishing_dataset.csv` |
| `notebooks/feature_extraction.ipynb` | Lexical feature engineering + automata feature application → `hybrid_dataset.csv` |
| `notebooks/model_training.ipynb` | Baseline vs. hybrid comparison, cheat-feature analysis, final model training + save |
| `notebooks/train_email_model.ipynb` | TF-IDF vectorization, RF training, email model save |
| `notebooks/email_exploration.ipynb` | EDA on email dataset: class balance, sample inspection |
| `frontend/src/App.jsx` | React SPA: URL/Email scanner, "How it Works" 3-step explainer, About page |
| `requirements.txt` | Full pinned dependency list |
| `pytest.ini` | Test discovery configuration |
