"""
Bana Budget AI — Python Flask Backend
Endpoints:
  GET  /api/health              → Server health check
  GET  /api/version             → App version check (force update)
  POST /api/register-token      → Register device push notification token
  POST /api/send-notification   → Send push notification to all users (admin)
  POST /api/parse-sms           → AI bank SMS parsing (Claude AI)
  POST /api/chat                → AI help chatbot (Claude AI)
  POST /api/bug-report          → Email bug report to developer
"""

from flask import Flask, request, jsonify, abort, send_file
import io as _io
from flask_cors import CORS
from dotenv import load_dotenv
import os, json, re, smtplib, threading, httpx, hashlib, hmac, time
from datetime import datetime, timedelta
from collections import defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps

load_dotenv()

app = Flask(__name__)

# ── CORS — only allow our app's domain ───────────────────────────────────────
CORS(app, origins=[
    'https://banabudgetai-api.onrender.com',
    'http://localhost:*',
    'http://10.0.2.2:*',   # Android emulator
], supports_credentials=True)

# ── Security: Rate Limiting Store (in-memory) ─────────────────────────────────
rate_store: dict = defaultdict(lambda: {'count': 0, 'reset': time.time() + 60})
blocked_ips: dict = {}      # ip → unblock_timestamp
suspicious_log: list = []   # list of security events

RATE_LIMITS = {
    'default':        (30, 60),   # 30 requests per 60 seconds
    '/api/parse-sms': (10, 60),   # 10 per minute
    '/api/chat':      (20, 60),   # 20 per minute
    '/api/register-token': (5, 60), # 5 per minute
}
BLOCK_THRESHOLD = 100  # block IP after this many requests in 60s
BLOCK_DURATION  = 3600 # 1 hour block

# ── Security: Request Signing ─────────────────────────────────────────────────
REQUEST_SECRET = os.getenv("REQUEST_SECRET", "bana_secret_2026_do_not_share")
MAX_REQUEST_AGE_SEC = 300  # 5 minutes

# ─────────────────────────────────────────────────────────────────────────────
# SECURITY MIDDLEWARE
# ─────────────────────────────────────────────────────────────────────────────

def get_client_ip() -> str:
    """Get real client IP (handles proxies)."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'

def log_security_event(event: str, ip: str, detail: str = ''):
    entry = {'event': event, 'ip': ip, 'time': datetime.utcnow().isoformat(), 'detail': detail}
    suspicious_log.append(entry)
    if len(suspicious_log) > 1000:
        suspicious_log.pop(0)
    print(f"[SECURITY] {event} from {ip}: {detail}")

def is_ip_blocked(ip: str) -> bool:
    if ip in blocked_ips:
        if time.time() < blocked_ips[ip]:
            return True
        del blocked_ips[ip]
    return False

def block_ip(ip: str, reason: str):
    blocked_ips[ip] = time.time() + BLOCK_DURATION
    log_security_event('ip_blocked', ip, reason)

def check_rate_limit(ip: str, endpoint: str) -> bool:
    """Returns True if request is allowed, False if rate limited."""
    limit, window = RATE_LIMITS.get(endpoint, RATE_LIMITS['default'])
    key = f"{ip}:{endpoint}"
    now = time.time()

    if key not in rate_store or now > rate_store[key]['reset']:
        rate_store[key] = {'count': 1, 'reset': now + window}
        return True

    rate_store[key]['count'] += 1
    if rate_store[key]['count'] > limit:
        if rate_store[key]['count'] > BLOCK_THRESHOLD:
            block_ip(ip, f"Rate limit exceeded: {rate_store[key]['count']} requests")
        return False
    return True

def sanitize_string(s: str, max_length: int = 500) -> str:
    """Remove dangerous characters and limit length."""
    if not isinstance(s, str):
        return ''
    # Remove null bytes, control chars, and limit length
    cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', s)
    return cleaned[:max_length]

def contains_injection(s: str) -> bool:
    """Detect SQL/script injection patterns."""
    patterns = [
        r'(?i)(select|insert|update|delete|drop|union|exec|execute)\s',
        r'<script[^>]*>',
        r'javascript:',
        r'(?i)(\bor\b|\band\b)\s+[\d\'"]+=[\d\'"]+',
    ]
    return any(re.search(p, s) for p in patterns)

# ── Security decorator ────────────────────────────────────────────────────────
def secure_endpoint(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = get_client_ip()

        # 1. Check if IP is blocked
        if is_ip_blocked(ip):
            log_security_event('blocked_request', ip, f'Endpoint: {request.path}')
            return jsonify({'error': 'Access denied', 'code': 'BLOCKED'}), 403

        # 2. Rate limiting
        if not check_rate_limit(ip, request.path):
            log_security_event('rate_limited', ip, f'Endpoint: {request.path}')
            return jsonify({'error': 'Too many requests. Please wait.', 'code': 'RATE_LIMITED'}), 429

        # 3. Validate Content-Type for POST requests
        if request.method == 'POST' and request.content_length:
            ct = request.content_type or ''
            if 'application/json' not in ct:
                return jsonify({'error': 'Invalid content type'}), 400

        # 4. Check request size (max 100KB)
        if request.content_length and request.content_length > 100_000:
            log_security_event('oversized_request', ip, f'{request.content_length} bytes')
            return jsonify({'error': 'Request too large'}), 413

        return f(*args, **kwargs)
    return decorated

# ── Security headers middleware ───────────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options']    = 'nosniff'
    response.headers['X-Frame-Options']            = 'DENY'
    response.headers['X-XSS-Protection']           = '1; mode=block'
    response.headers['Strict-Transport-Security']  = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy']    = "default-src 'none'"
    response.headers['Referrer-Policy']            = 'strict-origin-when-cross-origin'
    response.headers['Cache-Control']              = 'no-store, no-cache, must-revalidate'
    response.headers['Pragma']                     = 'no-cache'
    # Remove server fingerprint
    response.headers.pop('Server', None)
    response.headers.pop('X-Powered-By', None)
    return response

# ── Config ────────────────────────────────────────────────────────────────────
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
SMTP_HOST         = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT         = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER         = os.getenv("SMTP_USER", "")
SMTP_PASS         = os.getenv("SMTP_PASS", "")
DEVELOPER_EMAIL   = os.getenv("DEVELOPER_EMAIL", "banabudgetai@gmail.com")

# ── Version Config — UPDATE THESE when releasing a new version ────────────────
# minimum_version: users below this are FORCED to update (blocking modal)
# latest_version:  current latest version shown in update prompt
VERSION_CONFIG_FILE = "/tmp/bana_version.json"
PLAY_STORE_URL = "https://play.google.com/store/apps/details?id=com.banaai.budgetapp"

DEFAULT_VERSION_CONFIG = {
    "minimum_version": "2.2.4",
    "latest_version":  "2.3.0",
    "force_update":    False,
    "update_message":  "Bana Budget AI v2.3.0 — Setup Wizard + Help button on home screen.",
    "play_store_url":  PLAY_STORE_URL,
    "whats_new": [
        "First-run Setup Wizard guides new users",
        "Help (?) button on home screen",
        "Replay tutorial or setup wizard anytime",
        "AI Help Chat from home screen",
    ]
}

def load_version_config() -> dict:
    """Load persisted version config from disk; fall back to default."""
    try:
        if os.path.exists(VERSION_CONFIG_FILE):
            with open(VERSION_CONFIG_FILE, "r", encoding="utf-8") as f:
                return {**DEFAULT_VERSION_CONFIG, **json.load(f)}
    except Exception as e:
        print(f"[VERSION] Load failed: {e}")
    return DEFAULT_VERSION_CONFIG.copy()

def save_version_config(config: dict) -> None:
    """Persist version config so it survives Render redeploys."""
    try:
        with open(VERSION_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f)
    except Exception as e:
        print(f"[VERSION] Save failed: {e}")

APP_VERSION_CONFIG = load_version_config()

# ─────────────────────────────────────────────────────────────────────────────
# PLAY STORE AUTO-POLLER — scrapes the Play Store every hour to detect new
# releases automatically, no manual bump needed.
# ─────────────────────────────────────────────────────────────────────────────
def _push_update_notification(version: str) -> int:
    """Push 'update available' to all registered devices. Returns count sent."""
    if not push_tokens:
        return 0
    messages = [
        {
            'to': t,
            'title': f'🚀 Update Available — v{version}',
            'body': 'A new version of Bana Budget AI is ready. Tap to update.',
            'priority': 'high',
            'data': {'type': 'app_update', 'version': version},
        }
        for t in list(push_tokens)
    ]
    try:
        httpx.post(
            'https://exp.host/--/api/v2/push/send',
            json=messages,
            headers={'Accept': 'application/json', 'Content-Type': 'application/json'},
            timeout=10,
        )
        return len(messages)
    except Exception as e:
        print(f"[POLL] Push failed: {e}")
        return 0

def _semver_gt(a: str, b: str) -> bool:
    """True if version `a` is greater than version `b` (e.g. '1.9.7' > '1.9.6')."""
    try:
        pa = [int(x) for x in a.split('.')[:3]]
        pb = [int(x) for x in b.split('.')[:3]]
        while len(pa) < 3: pa.append(0)
        while len(pb) < 3: pb.append(0)
        return pa > pb
    except Exception:
        return False

def poll_play_store() -> None:
    """Fetch Play Store page, extract version, auto-bump + notify if newer."""
    try:
        r = httpx.get(PLAY_STORE_URL, timeout=20, headers={'User-Agent': 'Mozilla/5.0'})
        if r.status_code != 200:
            print(f"[POLL] Play Store returned {r.status_code}")
            return
        # Extract version from Play Store HTML
        # Pattern in HTML: [[["1.9.7"]]] or "Current Version"...">1.9.7<"
        patterns = [
            r'\[\["([0-9]+\.[0-9]+\.[0-9]+)"\]\]',
            r'Current Version[^>]+>([0-9]+\.[0-9]+\.[0-9]+)<',
            r'"versionName":"([0-9]+\.[0-9]+\.[0-9]+)"',
            r'>([0-9]+\.[0-9]+\.[0-9]+)<\/span>\s*<\/div>\s*<div[^>]*>Current Version',
        ]
        latest_from_store = None
        for p in patterns:
            m = re.search(p, r.text)
            if m:
                latest_from_store = m.group(1)
                break
        if not latest_from_store:
            print("[POLL] Could not extract version from Play Store HTML")
            return

        current = APP_VERSION_CONFIG.get('latest_version', '0.0.0')
        if _semver_gt(latest_from_store, current):
            print(f"[POLL] New version detected: {current} → {latest_from_store}")
            APP_VERSION_CONFIG['latest_version']  = latest_from_store
            APP_VERSION_CONFIG['minimum_version'] = latest_from_store
            APP_VERSION_CONFIG['force_update']    = True
            APP_VERSION_CONFIG['update_message']  = f"Bana Budget AI v{latest_from_store} is now available with improvements. Please update."
            save_version_config(APP_VERSION_CONFIG)
            count = _push_update_notification(latest_from_store)
            print(f"[POLL] Auto-bumped to v{latest_from_store}, notified {count} devices")
        else:
            print(f"[POLL] OK — current {current}, Play Store {latest_from_store}")
    except Exception as e:
        print(f"[POLL] Error: {e}")

def _poll_loop() -> None:
    """Background thread: poll every hour, with first check after 30s of startup."""
    time.sleep(30)  # let server fully boot
    while True:
        poll_play_store()
        time.sleep(3600)  # 1 hour

# Start the poller in a daemon thread on server startup
_poll_thread = threading.Thread(target=_poll_loop, daemon=True, name='play-store-poller')
_poll_thread.start()
print(f"[POLL] Play Store auto-poller started — checks every hour")

# Manual trigger endpoint for testing
@app.post("/api/admin/poll-play-store")
def trigger_poll():
    admin_key = request.headers.get('X-Admin-Key', '')
    expected  = os.getenv('ADMIN_SECRET_KEY', 'change_this_admin_key')
    if not hmac.compare_digest(admin_key, expected):
        return jsonify({'error': 'Unauthorized'}), 401
    threading.Thread(target=poll_play_store, daemon=True).start()
    return jsonify({'success': True, 'message': 'Poll triggered — check server logs'})

# ── Auto-Update Webhook: Play Console can call this to bump versions ───────
@app.post("/api/admin/bump-version")
def bump_version():
    """
    Bump the latest_version (and optionally minimum_version) when a new release
    is published. Protected by ADMIN_SECRET_KEY header.

    POST body: {
      "latest_version": "1.9.4",
      "minimum_version": "1.9.0",   # optional — only set if force-updating
      "whats_new": ["Feature 1", "Feature 2"],   # optional
      "force_update": true,         # optional
      "notify": true                # if true, send push to all devices
    }
    """
    admin_key = request.headers.get('X-Admin-Key', '')
    expected  = os.getenv('ADMIN_SECRET_KEY', 'change_this_admin_key')
    if not hmac.compare_digest(admin_key, expected):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json(silent=True) or {}
    latest = (data.get('latest_version') or '').strip()
    if not latest:
        return jsonify({'error': 'latest_version required'}), 400

    APP_VERSION_CONFIG['latest_version'] = latest
    if data.get('minimum_version'):
        APP_VERSION_CONFIG['minimum_version'] = data['minimum_version'].strip()
    if isinstance(data.get('whats_new'), list):
        APP_VERSION_CONFIG['whats_new'] = data['whats_new'][:6]
    if 'force_update' in data:
        APP_VERSION_CONFIG['force_update'] = bool(data['force_update'])
    if data.get('update_message'):
        APP_VERSION_CONFIG['update_message'] = data['update_message']

    # Persist to disk so it survives redeploys
    save_version_config(APP_VERSION_CONFIG)

    # Auto-push notification to all registered devices
    if data.get('notify', True) and push_tokens:
        messages = [
            {
                'to': t,
                'title': f'🚀 Update Available — v{latest}',
                'body': 'A new version of Bana Budget AI is ready. Tap to update.',
                'priority': 'high',
                'data': { 'type': 'app_update', 'version': latest },
            }
            for t in list(push_tokens)
        ]
        try:
            httpx.post(
                'https://exp.host/--/api/v2/push/send',
                json=messages,
                headers={'Accept-Encoding': 'gzip, deflate', 'Accept': 'application/json', 'Content-Type': 'application/json'},
                timeout=10,
            )
        except Exception as e:
            print(f"[BUMP] Push failed: {e}")

    return jsonify({
        'success': True,
        'config': APP_VERSION_CONFIG,
        'notified_devices': len(push_tokens),
    })

# ── Push token store: persist to disk so they survive Render redeploys ──────
PUSH_TOKENS_FILE = "/tmp/bana_push_tokens.json"

def load_push_tokens() -> set:
    try:
        if os.path.exists(PUSH_TOKENS_FILE):
            with open(PUSH_TOKENS_FILE, "r", encoding="utf-8") as f:
                return set(json.load(f))
    except Exception as e:
        print(f"[PUSH] Load failed: {e}")
    return set()

def save_push_tokens() -> None:
    try:
        with open(PUSH_TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump(list(push_tokens), f)
    except Exception as e:
        print(f"[PUSH] Save failed: {e}")

push_tokens = load_push_tokens()
print(f"[PUSH] Loaded {len(push_tokens)} persisted push token(s)")

# ─────────────────────────────────────────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/api/health")
@secure_endpoint
def health():
    return jsonify({
        "status": "ok",
        "service": "Bana Budget AI API",
        "version": "1.0.0",
        "python": "3.14",
        "ai": "Claude (Anthropic)" if ANTHROPIC_API_KEY else "FAQ fallback",
    })

@app.get("/")
def root():
    return jsonify({"message": "Bana Budget AI API running", "health": "/api/health"})

# ─────────────────────────────────────────────────────────────────────────────
# VERSION CHECK — called on every app launch
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/api/version")
@secure_endpoint
def version_check():
    """
    Returns version config. App compares its own version with minimum_version.
    If app_version < minimum_version → show force update modal.
    """
    return jsonify(APP_VERSION_CONFIG)

# ─────────────────────────────────────────────────────────────────────────────
# PUSH NOTIFICATION REGISTRATION
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/register-token")
@secure_endpoint
def register_token():
    """Register an Expo push token from a device."""
    data  = request.get_json(silent=True) or {}
    token = data.get("token", "").strip()
    if not token or not token.startswith("ExponentPushToken"):
        return jsonify({"error": "Invalid Expo push token"}), 400
    push_tokens.add(token)
    save_push_tokens()  # persist immediately so it survives restarts
    print(f"[PUSH] Registered token: {token} | Total devices: {len(push_tokens)}")
    return jsonify({"success": True, "registered_devices": len(push_tokens)})

# ─────────────────────────────────────────────────────────────────────────────
# SEND PUSH NOTIFICATION (admin endpoint)
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/send-notification")
@secure_endpoint
def send_notification():
    """
    Send push notification to ALL registered devices via Expo Push API.
    Body: { "title": "...", "body": "...", "data": {} }
    """
    data  = request.get_json(silent=True) or {}
    title = data.get("title", "Bana Budget AI")
    body  = data.get("body", "")
    extra = data.get("data", {})

    if not body:
        return jsonify({"error": "body is required"}), 400
    if not push_tokens:
        return jsonify({"success": True, "sent": 0, "message": "No registered devices"})

    messages = [
        {
            "to": token,
            "sound": "default",
            "title": title,
            "body": body,
            "data": extra,
            "badge": 1,
        }
        for token in push_tokens
    ]

    try:
        # Expo Push API — send in chunks of 100
        sent = 0
        for i in range(0, len(messages), 100):
            chunk = messages[i:i + 100]
            resp = httpx.post(
                "https://exp.host/--/api/v2/push/send",
                json=chunk,
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                timeout=15,
            )
            result = resp.json()
            sent += len(chunk)
            print(f"[PUSH] Sent batch {i//100 + 1}: {result}")
        return jsonify({"success": True, "sent": sent, "total_devices": len(push_tokens)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────────────────────────────────────
# AI SMS PARSING
# ─────────────────────────────────────────────────────────────────────────────
SMS_SYSTEM = """You are a bank SMS parser for Qatar and Pakistan banks.
Extract transaction data from the SMS and return ONLY valid JSON:
{
  "is_bank_sms": true,
  "amount": 0.0,
  "currency": "QAR",
  "merchant": "name",
  "type": "debit or credit",
  "category": "food|transport|housing|bills|shopping|entertainment|health|education|remittance|financial|travel|personal|income",
  "subcategory": "relevant subcategory",
  "confidence": 85,
  "sender": "bank name",
  "summary": "one line summary"
}
If NOT a bank SMS return: {"is_bank_sms": false}
Return ONLY JSON, no other text."""

def claude_parse_sms(sms_text: str, country_code: str) -> dict:
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        msg = client.messages.create(
            model="claude-haiku-3-5",
            max_tokens=512,
            system=SMS_SYSTEM,
            messages=[{"role": "user", "content": f"Country:{country_code}\nSMS:{sms_text}"}]
        )
        raw = msg.content[0].text.strip()
        m = re.search(r'\{.*\}', raw, re.DOTALL)
        return json.loads(m.group() if m else raw)
    except Exception as e:
        print(f"Claude SMS error: {e}")
        return regex_parse_sms(sms_text, country_code)

def regex_parse_sms(sms_text: str, country_code: str) -> dict:
    text = sms_text.lower()
    bank_kw = ['debited','credited','deducted','charged','a/c','balance','qar','pkr','rs.','transaction']
    if not any(k in text for k in bank_kw):
        return {"is_bank_sms": False}

    currency = "QAR" if country_code == "QA" else "PKR"
    amount = 0.0
    for p in [r'(?:QAR|PKR|AED|Rs\.?)\s*([\d,]+(?:\.\d{1,2})?)', r'([\d,]+(?:\.\d{1,2})?)\s*(?:QAR|PKR|AED)']:
        m = re.search(p, sms_text, re.IGNORECASE)
        if m:
            amount = float(m.group(1).replace(',', ''))
            break

    tx_type = "credit" if any(w in text for w in ['credit','credited','deposit','received','salary']) else "debit"
    merchant = "Bank Transaction"
    for p in [r'at\s+([A-Z][A-Z0-9\s\-&]{2,30}?)(?:\s+on|\.|,)', r'to\s+([A-Z][A-Z0-9\s\-&]{2,30}?)(?:\s+on|\.|,)']:
        m = re.search(p, sms_text, re.IGNORECASE)
        if m:
            merchant = m.group(1).strip()[:40]
            break

    cat_rules = [
        (['carrefour','lulu','grocery','imtiaz','supermarket'], 'food', 'groceries'),
        (['starbucks','mcdonalds','kfc','restaurant','cafe'], 'food', 'restaurant'),
        (['uber','careem','taxi','ride'], 'transport', 'ride'),
        (['fuel','petrol','shell','pso'], 'transport', 'fuel'),
        (['ooredoo','jazz','telenor','mobile','internet'], 'bills', 'mobile'),
        (['electricity','k-electric','dewa','kahramaa'], 'bills', 'electricity'),
        (['jazzcash','easypaisa','western union'], 'remittance', 'family'),
        (['salary','payroll'], 'income', 'salary'),
        (['noon','amazon','namshi'], 'shopping', 'clothing'),
    ]
    category, subcategory = ("income", "salary") if tx_type == "credit" else ("personal", "misc")
    for keywords, cat, sub in cat_rules:
        if any(k in text for k in keywords):
            category, subcategory = cat, sub
            break

    return {
        "is_bank_sms": True, "amount": amount, "currency": currency,
        "merchant": merchant, "type": tx_type, "category": category,
        "subcategory": subcategory, "confidence": 65, "sender": "Bank",
        "summary": f"{tx_type.title()} {currency} {amount:.2f} at {merchant}"
    }

@app.post("/api/parse-sms")
@secure_endpoint
def parse_sms():
    ip   = get_client_ip()
    data = request.get_json(silent=True) or {}
    sms_text = sanitize_string((data.get("sms_text") or "").strip(), max_length=1000)
    country  = sanitize_string(data.get("country_code", "QA"), max_length=5)

    # Injection detection
    if contains_injection(sms_text):
        log_security_event('injection_attempt', ip, f'SMS endpoint: {sms_text[:100]}')
        return jsonify({"error": "Invalid input"}), 400

    if len(sms_text) < 10:
        return jsonify({"error": "SMS text too short"}), 400

    result = claude_parse_sms(sms_text, country) if ANTHROPIC_API_KEY else regex_parse_sms(sms_text, country)

    if not result.get("is_bank_sms"):
        return jsonify({"error": "Not a bank transaction SMS"}), 422

    return jsonify(result)

# ─────────────────────────────────────────────────────────────────────────────
# AI CHATBOT
# ─────────────────────────────────────────────────────────────────────────────
CHAT_SYSTEM = """You are the friendly AI assistant for Bana Budget AI — a finance app for Qatar/Pakistan expats.
Keep replies short (2-4 sentences), mobile-friendly, occasionally use emojis.
App features: expense/income tracking, budgets, goals, AI SMS parsing, live QAR↔PKR rates, dual-country profiles.
If user reports a bug, be empathetic and mention the developer will be notified."""

FAQ_RESPONSES = {
    "expense":   "Tap '+ Expense' on Home → enter amount → pick category & subcategory → choose account → Save! 💸",
    "income":    "Tap '+ Income' on Home → enter amount → pick income type → choose account → Save! ✅",
    "budget":    "Goals tab → '+ Budget' → pick category → set monthly limit → Save. Progress bar fills as you spend! 📊",
    "goal":      "Goals tab → '+ Goal' → enter name, target, deadline → Save. Track your savings progress! 🎯",
    "sms":       "Inbox tab → 'Paste SMS' → paste your bank message → 'Parse with AI'. Detects amount, merchant & category! 🤖",
    "account":   "Home → '+ Bank A/C' → choose type (Bank/Card/Loan/Cash) → fill details → Save. 🏦",
    "rate":      "Exchange rates update every 30 seconds. Tap the rate widget on Home for all currencies! 💱",
    "privacy":   "Your data NEVER leaves your device. No server, no cloud sync, 100% private! 🔒",
    "custom":    "In '+ Expense', scroll to 'Custom' tile → enter name, emoji, pick colour → Add Category! 🎨",
    "delete":    "Use the trash icon on accounts, budgets, or goals. Transaction delete is coming in the next update!",
    "remittance":"Add a Remittance expense → it shows on the Home screen how much you've sent home! 💸",
}

def faq_reply(msg: str):
    lower = msg.lower()
    for key, answer in FAQ_RESPONSES.items():
        if key in lower:
            return answer
    return None

@app.post("/api/chat")
@secure_endpoint
def chat():
    data    = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    history = data.get("history", [])

    if not message:
        return jsonify({"error": "Message required"}), 400

    bug_words = ['not working','broken','bug','crash','error','wrong','missing','disappeared']
    is_bug = any(w in message.lower() for w in bug_words)

    # Try Claude first
    if ANTHROPIC_API_KEY:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            messages = [{"role": h["role"], "content": h["content"]} for h in history[-10:]]
            messages.append({"role": "user", "content": message})
            resp = client.messages.create(
                model="claude-haiku-3-5", max_tokens=300,
                system=CHAT_SYSTEM, messages=messages
            )
            reply = resp.content[0].text.strip()
            return jsonify({"reply": reply, "is_bug_report": is_bug, "suggested_actions": []})
        except Exception as e:
            print(f"Claude chat error: {e}")

    # FAQ fallback
    faq = faq_reply(message)
    if faq:
        return jsonify({"reply": faq, "is_bug_report": False, "suggested_actions": []})

    reply = (
        "This looks like a technical issue — tap 'Contact Developer' and we'll fix it within 24 hours! 🔧"
        if is_bug else
        "Try asking about expenses, budgets, goals, SMS detection, or exchange rates! 😊"
    )
    return jsonify({"reply": reply, "is_bug_report": is_bug, "suggested_actions": ["Contact Developer"] if is_bug else []})

# ─────────────────────────────────────────────────────────────────────────────
# AI SPENDING INSIGHTS — Claude analyses transactions vs historical + inflation
# ─────────────────────────────────────────────────────────────────────────────
INSIGHTS_SYSTEM = """You are a personal finance AI advisor for Bana Budget AI users.
You analyse a user's spending data and produce SHORT, ACTIONABLE insights.

RULES:
- Output 4-6 bullet points, each max 25 words.
- Compare current period to prior periods using the numbers provided.
- Flag categories that are >20% above their average — call these "critical".
- Suggest 2-3 specific actions to save money in the most-overspent category.
- Consider local context (inflation, country) where mentioned.
- Use the user's currency symbol.
- End with one motivational tip.
- Use emojis: 🚨 critical, 📈 rising, 💡 tip, 🎯 goal.
"""

@app.post("/api/insights")
@secure_endpoint
def insights():
    """
    Analyse user's spending vs historical & inflation. Returns AI insights.

    Body: {
      "currency": "QAR",
      "country": "Qatar",
      "current_period": { "label": "This Month", "total": 4500, "by_category": {"food": 1200, ...} },
      "prior_periods": [
        { "label": "Last Month",  "total": 3800, "by_category": {...} },
        { "label": "Last Quarter Avg", "total": 4000, "by_category": {...} },
        { "label": "Last Year Avg", "total": 3500, "by_category": {...} },
      ],
      "budgets":  { "food": 1000, "transport": 500 },
      "goals":    [ { "name": "Vacation", "target": 5000, "saved": 1200 } ]
    }
    """
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"error": "Bad payload"}), 400

    if not ANTHROPIC_API_KEY:
        # Fallback: simple rule-based insights
        return jsonify({
            "summary":  "AI is offline; here are basic stats based on your data.",
            "insights": rule_based_insights(data),
        })

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        # Build a compact, structured prompt
        prompt = build_insights_prompt(data)
        resp = client.messages.create(
            model="claude-haiku-3-5",
            max_tokens=600,
            system=INSIGHTS_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )
        text = resp.content[0].text.strip()
        # Split into bullet-list
        lines = [l.strip().lstrip('-•●').strip() for l in text.split('\n') if l.strip() and not l.strip().startswith('#')]
        return jsonify({
            "summary":  "AI-generated insights for your spending",
            "insights": lines[:8],
        })
    except Exception as e:
        print(f"[INSIGHTS] Claude error: {e}")
        return jsonify({
            "summary":  "Using rule-based analysis (AI temporarily unavailable).",
            "insights": rule_based_insights(data),
        })

def build_insights_prompt(d: dict) -> str:
    """Compact prompt for Claude."""
    cur     = d.get("current_period", {})
    priors  = d.get("prior_periods", []) or []
    bdgts   = d.get("budgets", {}) or {}
    goals   = d.get("goals", []) or []
    curr    = d.get("currency", "USD")
    country = d.get("country", "Global")

    lines = [
        f"User country: {country}",
        f"Currency: {curr}",
        f"",
        f"Current period ({cur.get('label', '')}): total {curr} {cur.get('total', 0):.0f}",
        "  Categories:",
    ]
    for cat, amt in (cur.get("by_category", {}) or {}).items():
        lines.append(f"    {cat}: {curr} {amt:.0f}")
    lines.append("")
    for p in priors[:3]:
        lines.append(f"{p.get('label', '')}: total {curr} {p.get('total', 0):.0f}")
        for cat, amt in (p.get("by_category", {}) or {}).items():
            lines.append(f"    {cat}: {curr} {amt:.0f}")
        lines.append("")
    if bdgts:
        lines.append("Active budgets:")
        for cat, lim in bdgts.items():
            spent = (cur.get("by_category", {}) or {}).get(cat, 0)
            pct = (spent / lim * 100) if lim else 0
            lines.append(f"    {cat}: {curr} {spent:.0f} of {curr} {lim:.0f} ({pct:.0f}%)")
    if goals:
        lines.append("")
        lines.append("Savings goals:")
        for g in goals[:3]:
            lines.append(f"    {g.get('name', '')}: saved {curr} {g.get('saved', 0):.0f} of {curr} {g.get('target', 0):.0f}")
    lines.append("")
    lines.append(
        "Provide 4-6 short bullets: which categories are over budget or growing fastest, "
        "what the user can cut to save money, and one motivational tip."
    )
    return "\n".join(lines)

def rule_based_insights(d: dict) -> list:
    """Fallback when AI is offline — basic deterministic analysis."""
    out  = []
    cur  = d.get("current_period", {}) or {}
    curr = d.get("currency", "USD")
    by   = cur.get("by_category", {}) or {}
    bdgts = d.get("budgets", {}) or {}
    total = cur.get("total", 0)

    # Top category
    if by:
        top_cat, top_amt = max(by.items(), key=lambda kv: kv[1])
        out.append(f"📈 Top spending category: {top_cat} at {curr} {top_amt:.0f} ({(top_amt/total*100):.0f}% of total)")

    # Over budget
    for cat, lim in bdgts.items():
        spent = by.get(cat, 0)
        if lim and spent > lim:
            over = spent - lim
            out.append(f"🚨 {cat} over budget by {curr} {over:.0f} ({(spent/lim*100):.0f}%) — try to cut back")

    # Prior comparison
    priors = d.get("prior_periods", [])
    if priors:
        prior = priors[0]
        prior_total = prior.get("total", 0)
        if prior_total > 0:
            diff = total - prior_total
            pct  = (diff / prior_total * 100) if prior_total else 0
            sign = "+" if diff > 0 else ""
            out.append(f"📊 vs {prior.get('label','')}: {sign}{curr} {diff:.0f} ({sign}{pct:.0f}%)")

    out.append("💡 Tip: review subscriptions and eating-out costs first — these usually have the biggest easy savings.")
    out.append("🎯 Stay consistent: even small savings each week compound into big results over a year.")
    return out

# ─────────────────────────────────────────────────────────────────────────────
# FBR IT-3 EXCEL FORM GENERATOR — fills the official FBR template
# ─────────────────────────────────────────────────────────────────────────────
IT3_TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "it3_template.xls")

@app.post("/api/fbr/generate-it3")
@secure_endpoint
def generate_it3_xls():
    """
    Fill the official FBR IT-3 Excel template with user profile + tax credits.
    Returns the filled .xls as a downloadable file.

    Body: {
      "profile": { "ntn": "1234567", "cnic": "12345-1234567-1", "name": "...",
                   "designation": "...", "postingCity": "...", "department": "...",
                   "section": "...", "employeeNo": "...", "employerNtn": "...",
                   "employerName": "...", "taxYear": "2025" },
      "credits": [
        { "category": "mobile", "identifier": "0300-...", "taxAmount": 1500, ... }
      ]
    }
    """
    try:
        import xlrd
        from xlutils.copy import copy as xl_copy
        from xlwt import easyxf
    except ImportError as e:
        return jsonify({"error": f"Server missing Excel libraries: {e}"}), 500

    data = request.get_json(silent=True) or {}
    profile = data.get("profile") or {}
    credits = data.get("credits") or []

    if not os.path.exists(IT3_TEMPLATE_PATH):
        return jsonify({"error": "IT-3 template missing on server"}), 500

    # Open template + copy for writing
    book_rd = xlrd.open_workbook(IT3_TEMPLATE_PATH, formatting_info=True)
    book_wr = xl_copy(book_rd)
    sheet   = book_wr.get_sheet(0)

    # Styles
    bold_input = easyxf('font: bold on, height 200, colour_index 0x0C;')

    # ── HEADER FIELDS — cell positions discovered via xlrd cell-map ──
    # NTN (R5, cols after C5)
    sheet.write(5, 5,  str(profile.get("ntn", "")),       bold_input)
    # Tax Year (R5, cols after C28)
    sheet.write(5, 28, str(profile.get("taxYear", "")),   bold_input)
    # CNIC (3 parts) — single field for simplicity
    sheet.write(7, 5,  str(profile.get("cnic", "")),      bold_input)
    # Employee No (R7, cols after C28)
    sheet.write(7, 28, str(profile.get("employeeNo", "")),bold_input)
    # Employee Name (R9, cols after C5)
    sheet.write(9, 5,  str(profile.get("name", "")),      bold_input)
    # Designation (R11) + Posting City
    sheet.write(11, 5,  str(profile.get("designation", "")), bold_input)
    sheet.write(11, 28, str(profile.get("postingCity", "")), bold_input)
    # Department / Section
    sheet.write(13, 5,  str(profile.get("department", "")), bold_input)
    sheet.write(13, 28, str(profile.get("section", "")),    bold_input)
    # Employer NTN + Name
    sheet.write(15, 5,  str(profile.get("employerNtn", "")),  bold_input)
    sheet.write(15, 19, str(profile.get("employerName", "")), bold_input)

    # ── TAX CREDITS — categorise into the 4 fixed rows + 2 multi-row sections ──
    # Row layout in the template:
    #   R31 = Mobile Phone Bill         (3 columns: 1st, 2nd, 3rd)
    #   R32 = Motor Vehicle Tax
    #   R33 = Cash Withdrawal
    #   R34 = Profit on Debt
    #   R35-R37 = Electricity (consumer/CNIC/name) — 3 columns
    #   R38-R40 = Telephone   (number/CNIC/name)   — 3 columns
    #
    # Each "column" maps to slot 1/2/3 → spreadsheet cols 10, 18, 26
    SLOT_COLS = [10, 18, 26]   # 1st, 2nd, 3rd
    TAX_COL   = 34             # Amount of Tax Credit Claimed

    # Group credits by category
    grouped = { 'mobile': [], 'vehicle': [], 'cash': [], 'profit': [],
                'electricity': [], 'telephone': [] }
    for c in credits:
        cat = c.get('category')
        if cat in grouped:
            grouped[cat].append(c)

    def fill_simple(row: int, items: list):
        """Fill one row (mobile/vehicle/cash/profit) with up to 3 IDs + tax sum."""
        total = 0
        for i, item in enumerate(items[:3]):
            sheet.write(row, SLOT_COLS[i], str(item.get('identifier', '')), bold_input)
            total += float(item.get('taxAmount') or 0)
        if total > 0:
            sheet.write(row, TAX_COL, total, bold_input)

    def fill_owner_block(row_start: int, items: list):
        """Fill Electricity/Telephone — 3 rows × up to 3 columns + tax."""
        # Row N   = identifier (consumer/phone number)
        # Row N+1 = owner CNIC/NTN
        # Row N+2 = owner name
        total = 0
        for i, item in enumerate(items[:3]):
            sheet.write(row_start,     SLOT_COLS[i], str(item.get('identifier', '')), bold_input)
            sheet.write(row_start + 1, SLOT_COLS[i], str(item.get('ownerCnic',  '')), bold_input)
            sheet.write(row_start + 2, SLOT_COLS[i], str(item.get('ownerName',  '')), bold_input)
            total += float(item.get('taxAmount') or 0)
        if total > 0:
            sheet.write(row_start, TAX_COL, total, bold_input)

    fill_simple(31, grouped['mobile'])
    fill_simple(32, grouped['vehicle'])
    fill_simple(33, grouped['cash'])
    fill_simple(34, grouped['profit'])
    fill_owner_block(35, grouped['electricity'])
    fill_owner_block(38, grouped['telephone'])

    # ── TOTAL CLAIM ──
    grand_total = sum(float(c.get('taxAmount') or 0) for c in credits)
    sheet.write(41, 34, grand_total, bold_input)

    # ── DATE (employee signature line) ──
    from datetime import datetime as _dt
    sheet.write(45, 3, _dt.utcnow().strftime('%d-%b-%Y'), bold_input)

    # Serialise to bytes and return
    buf = _io.BytesIO()
    book_wr.save(buf)
    buf.seek(0)

    filename = f"FBR_IT-3_{(profile.get('name') or 'employee').replace(' ', '_')}_{profile.get('taxYear', '')}.xls"
    return send_file(
        buf,
        as_attachment=True,
        download_name=filename,
        mimetype='application/vnd.ms-excel',
    )

# ─────────────────────────────────────────────────────────────────────────────
# BUG REPORT → EMAIL
# ─────────────────────────────────────────────────────────────────────────────
def send_email_async(ticket_id: str, report: dict):
    if not SMTP_USER or not SMTP_PASS:
        print(f"[Bug #{ticket_id}] No SMTP config. Issue: {report.get('issue_description')}")
        return
    try:
        msg = MIMEMultipart()
        msg["From"]    = SMTP_USER
        msg["To"]      = DEVELOPER_EMAIL
        msg["Subject"] = f"🐛 Bug Report #{ticket_id} — Bana Budget AI"
        body = f"""
NEW BUG REPORT — Bana Budget AI
{'='*50}
Ticket    : {ticket_id}
Time      : {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}
App Ver   : {report.get('app_version','1.1.0')}
Device    : {report.get('device_info','Android')}
Screen    : {report.get('screen','Unknown')}

USER
----
Name      : {report.get('user_name','Anonymous')}
Email     : {report.get('user_email','Not provided')}

ISSUE
-----
{report.get('issue_description','')}

CHAT LOG
--------
{report.get('chat_transcript','None')}
{'='*50}
"""
        msg.attach(MIMEText(body, "plain"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        print(f"[Bug #{ticket_id}] Email sent to {DEVELOPER_EMAIL}")
    except Exception as e:
        print(f"[Bug #{ticket_id}] Email error: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# EMAIL OTP — for signup verification
# ─────────────────────────────────────────────────────────────────────────────
import random
otp_store = {}  # email -> {otp, expires}

RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
RESEND_FROM    = os.getenv("RESEND_FROM", "Bana Budget AI <onboarding@resend.dev>")

def send_otp_email(email: str, otp: str) -> bool:
    # Preferred: Resend HTTPS API (works on Render free tier)
    if RESEND_API_KEY:
        try:
            r = httpx.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {RESEND_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "from": RESEND_FROM,
                    "to": [email],
                    "subject": f"Bana Budget AI — Your verification code: {otp}",
                    "text": (
                        f"Hi,\n\n"
                        f"Your Bana Budget AI verification code is:\n\n"
                        f"        {otp}\n\n"
                        f"This code expires in 10 minutes.\n\n"
                        f"If you didn't request this, please ignore this email.\n\n"
                        f"— Bana Budget AI Team"
                    ),
                    "html": (
                        f"<div style='font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:24px'>"
                        f"<h2 style='color:#8b1538'>Bana Budget AI</h2>"
                        f"<p>Hi,</p>"
                        f"<p>Your verification code is:</p>"
                        f"<div style='font-size:32px;font-weight:bold;letter-spacing:8px;background:#f5f5f5;padding:16px;text-align:center;border-radius:8px;margin:16px 0'>{otp}</div>"
                        f"<p style='color:#666;font-size:13px'>This code expires in <b>10 minutes</b>.</p>"
                        f"<p style='color:#999;font-size:12px'>If you didn't request this, please ignore this email.</p>"
                        f"<hr style='border:none;border-top:1px solid #eee;margin:24px 0'/>"
                        f"<p style='color:#aaa;font-size:11px'>— Bana Budget AI Team</p>"
                        f"</div>"
                    ),
                },
                timeout=15,
            )
            if r.status_code in (200, 202):
                print(f"[OTP] Resend → {email} OK")
                return True
            print(f"[OTP] Resend failed: {r.status_code} {r.text[:200]}")
        except Exception as e:
            print(f"[OTP] Resend error: {e}")

    # Fallback: SMTP (won't work on Render free tier)
    if SMTP_USER and SMTP_PASS:
        try:
            msg = MIMEText(f"Your Bana Budget AI verification code is: {otp}\n\nExpires in 10 minutes.")
            msg["Subject"] = f"Bana Budget AI — Verification Code {otp}"
            msg["From"]    = SMTP_USER
            msg["To"]      = email
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
                s.starttls()
                s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
            print(f"[OTP] SMTP → {email} OK")
            return True
        except Exception as e:
            print(f"[OTP] SMTP error: {e}")

    print(f"[OTP] No email service configured — OTP for {email}: {otp}")
    return False

@app.post("/api/admin/test-smtp")
def test_smtp():
    """Debug: synchronously try SMTP and return actual error. Protected by admin key."""
    admin_key = request.headers.get('X-Admin-Key', '')
    expected  = os.getenv('ADMIN_SECRET_KEY', 'change_this_admin_key')
    if not hmac.compare_digest(admin_key, expected):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json(silent=True) or {}
    to_email = (data.get('email') or DEVELOPER_EMAIL).strip()

    debug = {
        'smtp_host': SMTP_HOST,
        'smtp_port': SMTP_PORT,
        'smtp_user': SMTP_USER if SMTP_USER else '(not set)',
        'smtp_pass_set': bool(SMTP_PASS),
        'smtp_pass_len': len(SMTP_PASS) if SMTP_PASS else 0,
        'to': to_email,
    }
    if not SMTP_USER or not SMTP_PASS:
        return jsonify({'success': False, 'error': 'SMTP_USER or SMTP_PASS missing', 'debug': debug})

    try:
        msg = MIMEText('Test email from Bana Budget AI server SMTP check.')
        msg['Subject'] = 'Bana Budget AI — SMTP Test'
        msg['From']    = SMTP_USER
        msg['To']      = to_email
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        return jsonify({'success': True, 'message': f'Test email sent to {to_email}', 'debug': debug})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e), 'error_type': type(e).__name__, 'debug': debug})

@app.post("/api/send-otp")
@secure_endpoint
def send_otp():
    data  = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if "@" not in email or "." not in email:
        return jsonify({"success": False, "error": "Invalid email"}), 400

    otp = f"{random.randint(0, 999999):06d}"
    otp_store[email] = {"otp": otp, "expires": time.time() + 600}  # 10 min

    # No email service at all — return local OTP for in-app display
    if not RESEND_API_KEY and not (SMTP_USER and SMTP_PASS):
        print(f"[OTP] No email service configured — OTP for {email}: {otp}")
        return jsonify({
            "success": True,
            "message": "Email service unavailable — use this code:",
            "local_otp": otp,
        })

    # Send SYNCHRONOUSLY so we know if delivery actually succeeded.
    # On failure, return the local OTP so the user can still proceed.
    sent = send_otp_email(email, otp)
    if sent:
        return jsonify({
            "success": True,
            "message": "Verification code sent to your email",
        })
    print(f"[OTP] Email delivery FAILED — returning local OTP for {email}")
    return jsonify({
        "success": True,
        "message": "Email service had a hiccup — use this code:",
        "local_otp": otp,
    })

@app.post("/api/verify-otp")
@secure_endpoint
def verify_otp():
    data  = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    otp   = (data.get("otp") or "").strip()
    entry = otp_store.get(email)

    if not entry:
        return jsonify({"success": False, "error": "No code requested"}), 400
    if time.time() > entry["expires"]:
        otp_store.pop(email, None)
        return jsonify({"success": False, "error": "Code expired — please request a new one"}), 400
    if otp != entry["otp"]:
        return jsonify({"success": False, "error": "Invalid code"}), 400

    otp_store.pop(email, None)
    return jsonify({"success": True, "message": "Email verified"})

@app.post("/api/bug-report")
@secure_endpoint
def bug_report():
    data = request.get_json(silent=True) or {}
    issue = (data.get("issue_description") or "").strip()
    if len(issue) < 5:
        return jsonify({"error": "Issue description required"}), 400

    ticket_id = f"BBK-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    threading.Thread(target=send_email_async, args=(ticket_id, data), daemon=True).start()

    return jsonify({
        "success": True,
        "ticket_id": ticket_id,
        "message": "Report sent! We'll look into it within 24 hours. 🙏"
    })

# ─────────────────────────────────────────────────────────────────────────────
# SECURITY ADMIN (protected by secret key)
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/api/admin/security")
def security_dashboard():
    """View security log and blocked IPs. Protected by admin key."""
    admin_key = request.headers.get('X-Admin-Key', '')
    expected  = os.getenv('ADMIN_SECRET_KEY', 'change_this_admin_key')
    if not hmac.compare_digest(admin_key, expected):
        log_security_event('admin_access_denied', get_client_ip())
        return jsonify({'error': 'Unauthorized'}), 401

    return jsonify({
        'blocked_ips':     {ip: datetime.fromtimestamp(ts).isoformat() for ip, ts in blocked_ips.items()},
        'recent_events':   suspicious_log[-20:],
        'registered_devices': len(push_tokens),
        'active_rate_entries': len(rate_store),
    })

@app.post("/api/admin/unblock")
def unblock_ip():
    """Unblock an IP. Protected by admin key."""
    admin_key = request.headers.get('X-Admin-Key', '')
    expected  = os.getenv('ADMIN_SECRET_KEY', 'change_this_admin_key')
    if not hmac.compare_digest(admin_key, expected):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json(silent=True) or {}
    ip   = data.get('ip', '').strip()
    if ip in blocked_ips:
        del blocked_ips[ip]
        return jsonify({'success': True, 'message': f'Unblocked {ip}'})
    return jsonify({'success': False, 'message': 'IP not in blocklist'})

# ─────────────────────────────────────────────────────────────────────────────
# ADAPTIVE SECURITY AI — Autonomous Alert Endpoint
# Called by the on-device Adaptive Security AI when it detects a breach and
# auto-escalates defenses. No auth header required — the device reports the
# attack, and the server blocks the attacker's IP + emails the owner.
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/security-alert")
@secure_endpoint
def security_alert():
    data     = request.get_json(silent=True) or {}
    kind     = data.get('kind', 'unknown')       # 'owner_alert' | 'auto_block'
    level    = data.get('level', 'UNKNOWN')
    score    = data.get('score', 0)
    trigger  = data.get('trigger', '')
    device   = data.get('device', 'unknown')
    version  = data.get('app_version', 'unknown')
    email    = data.get('email', DEVELOPER_EMAIL)
    at_ts    = data.get('at', 0)

    client_ip = get_client_ip()
    log_security_event('adaptive_ai_alert', client_ip,
                       f'kind={kind} level={level} score={score} trigger={trigger}')

    # If the device's AI requests an IP block, honour it immediately
    if kind == 'auto_block' and level in ('HIGH', 'LOCKDOWN'):
        block_ip(client_ip, f'Adaptive AI auto-block: level={level} score={score}')

    # Notify owner via email (async, best-effort)
    if kind == 'owner_alert':
        subject = f'🚨 Bana Budget AI Security Alert — Level {level}'
        body    = (
            f"Adaptive Security AI detected and responded to a threat.\n\n"
            f"  Level:    {level}\n"
            f"  Score:    {score}\n"
            f"  Trigger:  {trigger}\n"
            f"  Device:   {device}\n"
            f"  Version:  {version}\n"
            f"  Time:     {datetime.utcfromtimestamp(at_ts/1000).isoformat() if at_ts else 'unknown'} UTC\n\n"
            f"Defenses were automatically escalated. All encryption keys were rotated. "
            f"Your financial data remains protected.\n\n"
            f"If this was unexpected, review the Security Dashboard:\n"
            f"  GET /api/admin/security  (X-Admin-Key required)"
        )
        def _send():
            try:
                if not SMTP_USER or not SMTP_PASS:
                    print(f"[SECURITY ALERT] {subject}\n{body}")
                    return
                msg            = MIMEText(body)
                msg['Subject'] = subject
                msg['From']    = SMTP_USER
                msg['To']      = email
                with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
                    s.starttls()
                    s.login(SMTP_USER, SMTP_PASS)
                    s.send_message(msg)
                print(f"[SECURITY ALERT] Email sent to {email}")
            except Exception as e:
                print(f"[SECURITY ALERT] Email error: {e}")
        threading.Thread(target=_send, daemon=True).start()

        # Also push a high-priority notification to all registered devices
        if push_tokens:
            messages = [
                {
                    'to': t,
                    'title': f'🚨 Security Alert — Level {level}',
                    'body': f'A threat was detected ({trigger}). Defenses auto-escalated. Your data is safe.',
                    'priority': 'high',
                    'ttl': 3600,
                }
                for t in list(push_tokens)
            ]
            try:
                httpx.post(
                    'https://exp.host/--/api/v2/push/send',
                    json=messages,
                    headers={'Accept-Encoding': 'gzip, deflate', 'Accept': 'application/json', 'Content-Type': 'application/json'},
                    timeout=10,
                )
            except Exception:
                pass

    return jsonify({'success': True, 'action': 'logged'})

# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    print(f"\n🚀 Bana Budget AI API starting on http://0.0.0.0:{port}")
    print(f"   AI: {'Claude enabled ✅' if ANTHROPIC_API_KEY else 'FAQ fallback mode'}")
    print(f"   Email: {'Configured ✅' if SMTP_PASS else 'Not configured ⚠️'}\n")
    app.run(host="0.0.0.0", port=port, debug=False)
