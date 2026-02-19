"""
Quick test: start server + hit it with requests.

Tests:
1. GET /health
2. POST /process (returns ONLY {status, reply})
3. POST /process with artifacts (UPI, phone)
4. GET /export/session/<sessionId> (returns full evaluation structure)
"""
import sys, os, time, threading, json
sys.path.insert(0, os.path.dirname(__file__))

from anchor_api_server import app

def run():
    from werkzeug.serving import make_server
    srv = make_server('127.0.0.1', 5055, app, threaded=True)
    print("Server listening on http://127.0.0.1:5055", flush=True)
    srv.serve_forever()

t = threading.Thread(target=run, daemon=True)
t.start()
time.sleep(2)

import urllib.request
passed = 0
failed = 0

def check(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS: {name}", flush=True)
    else:
        failed += 1
        print(f"  FAIL: {name} — {detail}", flush=True)

# ── 1. Health check ─────────────────────────────────────────────
print("\n=== TEST 1: Health Check ===", flush=True)
try:
    req = urllib.request.Request("http://127.0.0.1:5055/health")
    resp = urllib.request.urlopen(req)
    data = json.loads(resp.read().decode())
    check("health returns 200", resp.status == 200)
    check("health has status=healthy", data.get("status") == "healthy")
except Exception as e:
    failed += 1
    print(f"  FAIL: Health check error: {e}", flush=True)

# ── 2. Process — basic scammer message ──────────────────────────
print("\n=== TEST 2: Process (basic message) ===", flush=True)
try:
    body = json.dumps({
        "sessionId": "test-eval-1",
        "message": {"text": "Hello sir this is Microsoft support your computer has virus", "sender": "scammer", "timestamp": "2026-02-10"},
        "conversationHistory": []
    }).encode()
    req = urllib.request.Request(
        "http://127.0.0.1:5055/process",
        data=body,
        headers={"Content-Type": "application/json", "x-api-key": "anchor-secret"},
        method="POST"
    )
    resp = urllib.request.urlopen(req)
    result = json.loads(resp.read().decode())
    
    check("process returns status=success", result.get("status") == "success")
    check("process returns non-empty reply", bool(result.get("reply")))
    # Response must contain: status, reply, scamDetected, intelligenceFlags + evaluation fields
    required_keys = {"status", "reply", "scamDetected", "intelligenceFlags",
                     "extractedIntelligence", "engagementMetrics", "agentNotes", "totalMessagesExchanged"}
    missing_keys = required_keys - set(result.keys())
    check("process returns all required keys", len(missing_keys) == 0,
          f"missing keys: {missing_keys}")
    check("process has scamDetected (bool)", isinstance(result.get("scamDetected"), bool))
    flags = result.get("intelligenceFlags", {})
    check("process has intelligenceFlags (dict)", isinstance(flags, dict))
    for fk in ["phoneNumber", "bankAccount", "upiId", "phishingLink", "emailAddress"]:
        check(f"intelligenceFlags.{fk} is bool", isinstance(flags.get(fk), bool))
except Exception as e:
    failed += 1
    print(f"  FAIL: Process error: {e}", flush=True)

# ── 3. Process — message with UPI & phone artifacts ─────────────
print("\n=== TEST 3: Process (with artifacts) ===", flush=True)
try:
    body = json.dumps({
        "sessionId": "test-eval-1",
        "message": {"text": "Please pay 5000 to kumar@ybl and call me at 9876543210", "sender": "scammer", "timestamp": "2026-02-10"},
        "conversationHistory": [
            {"sender": "scammer", "text": "Hello sir this is Microsoft support your computer has virus", "timestamp": "2026-02-10"},
            {"sender": "agent", "text": "Oh my, a virus? That sounds terrible!", "timestamp": "2026-02-10"},
        ]
    }).encode()
    req = urllib.request.Request(
        "http://127.0.0.1:5055/process",
        data=body,
        headers={"Content-Type": "application/json", "x-api-key": "anchor-secret"},
        method="POST"
    )
    resp = urllib.request.urlopen(req)
    result = json.loads(resp.read().decode())
    
    check("process with artifacts returns status=success", result.get("status") == "success")
    check("process with artifacts returns reply", bool(result.get("reply")))
    check("process with artifacts has extractedIntelligence", isinstance(result.get("extractedIntelligence"), dict))
    check("process with artifacts has engagementMetrics", isinstance(result.get("engagementMetrics"), dict))
    check("artifacts scamDetected is true", result.get("scamDetected") == True)
    flags = result.get("intelligenceFlags", {})
    check("artifacts upiId flag is true", flags.get("upiId") == True)
    check("artifacts phoneNumber flag is true", flags.get("phoneNumber") == True)
except Exception as e:
    failed += 1
    print(f"  FAIL: Process with artifacts error: {e}", flush=True)

# ── 4. Export session — verify exact evaluation structure ────────
print("\n=== TEST 4: Export Session ===", flush=True)
try:
    req = urllib.request.Request("http://127.0.0.1:5055/export/session/test-eval-1")
    resp = urllib.request.urlopen(req)
    export = json.loads(resp.read().decode())
    
    check("export returns sessionId", export.get("sessionId") == "test-eval-1")
    check("export has status field", export.get("status") == "completed")
    check("export has scamDetected (bool)", isinstance(export.get("scamDetected"), bool))
    check("export has totalMessagesExchanged (int)", isinstance(export.get("totalMessagesExchanged"), int))
    
    intel = export.get("extractedIntelligence", {})
    check("export has extractedIntelligence", isinstance(intel, dict))
    check("intel has phoneNumbers", isinstance(intel.get("phoneNumbers"), list))
    check("intel has bankAccounts", isinstance(intel.get("bankAccounts"), list))
    check("intel has upiIds", isinstance(intel.get("upiIds"), list))
    check("intel has phishingLinks", isinstance(intel.get("phishingLinks"), list))
    check("intel has emailAddresses", isinstance(intel.get("emailAddresses"), list))
    
    metrics = export.get("engagementMetrics", {})
    check("export has engagementMetrics", isinstance(metrics, dict))
    check("metrics has totalMessagesExchanged", isinstance(metrics.get("totalMessagesExchanged"), int))
    check("metrics has engagementDurationSeconds", isinstance(metrics.get("engagementDurationSeconds"), int))
    
    check("export has agentNotes (str)", isinstance(export.get("agentNotes"), str))
    
    # Verify artifacts were captured
    check("UPI ID kumar@ybl captured", "kumar@ybl" in intel.get("upiIds", []))
    
    print(f"\n  Export JSON:\n{json.dumps(export, indent=2)}", flush=True)
except Exception as e:
    failed += 1
    print(f"  FAIL: Export error: {e}", flush=True)

# ── 5. Export unknown session — graceful empty response ─────────
print("\n=== TEST 5: Export Unknown Session ===", flush=True)
try:
    req = urllib.request.Request("http://127.0.0.1:5055/export/session/nonexistent-session")
    resp = urllib.request.urlopen(req)
    export = json.loads(resp.read().decode())
    
    check("unknown session returns sessionId", export.get("sessionId") == "nonexistent-session")
    check("unknown session has status", export.get("status") == "completed")
    check("unknown session scamDetected=false", export.get("scamDetected") == False)
    check("unknown session totalMessages=0", export.get("totalMessagesExchanged") == 0)
except Exception as e:
    failed += 1
    print(f"  FAIL: Unknown session export error: {e}", flush=True)

# ── Summary ──────────────────────────────────────────────────────
print(f"\n{'='*50}", flush=True)
print(f"RESULTS: {passed} passed, {failed} failed", flush=True)
print(f"{'='*50}", flush=True)
if failed > 0:
    sys.exit(1)
