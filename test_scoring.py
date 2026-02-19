"""
Simulate the exact evaluate_final_output() scoring function
against the output of our /process and /export endpoints.
"""
import sys, os, time, threading, json
sys.path.insert(0, os.path.dirname(__file__))

from anchor_api_server import app


def evaluate_final_output(final_output):
    """Exact replica of the evaluator's scoring function."""
    score = 0
    details = {}

    # 1. Scam Detection (20 pts)
    sd = 0
    if final_output.get("scamDetected") == True:
        sd = 20
    details["scamDetection"] = sd
    score += sd

    # 2. Intelligence Extraction (40 pts, +10 per category, max 40)
    ie = 0
    intel = final_output.get("extractedIntelligence", {})
    for cat in ["phoneNumbers", "bankAccounts", "upiIds", "phishingLinks", "emailAddresses"]:
        if intel.get(cat) and len(intel[cat]) > 0:
            ie += 10
    ie = min(ie, 40)
    details["intelligenceExtraction"] = ie
    score += ie

    # 3. Engagement Quality (20 pts)
    eq = 0
    metrics = final_output.get("engagementMetrics", {})
    duration = metrics.get("engagementDurationSeconds", 0)
    messages = metrics.get("totalMessagesExchanged", 0)
    if duration > 0:
        eq += 5
    if duration > 60:
        eq += 5
    if messages > 0:
        eq += 5
    if messages >= 5:
        eq += 5
    details["engagementQuality"] = eq
    score += eq

    # 4. Response Structure (20 pts)
    rs = 0
    for key in ["status", "scamDetected", "extractedIntelligence"]:
        if key in final_output:
            rs += 5
    if "engagementMetrics" in final_output:
        rs += 2.5
    if "agentNotes" in final_output:
        rs += 2.5
    details["responseStructure"] = rs
    score += rs

    return score, details


def run():
    from werkzeug.serving import make_server
    srv = make_server("127.0.0.1", 5056, app, threaded=True)
    srv.serve_forever()


t = threading.Thread(target=run, daemon=True)
t.start()
time.sleep(2)

import urllib.request

BASE = "http://127.0.0.1:5056"
SESSION = "scoring-test-1"


def post_process(message_text, history):
    body = json.dumps({
        "sessionId": SESSION,
        "message": {"text": message_text, "sender": "scammer", "timestamp": "2026-02-10"},
        "conversationHistory": history,
    }).encode()
    req = urllib.request.Request(
        f"{BASE}/process",
        data=body,
        headers={"Content-Type": "application/json", "x-api-key": "anchor-secret"},
        method="POST",
    )
    resp = urllib.request.urlopen(req)
    return json.loads(resp.read().decode())


# Simulate a full 5-turn scam conversation with all artifact categories
messages = [
    "Hello sir this is Microsoft support your computer has virus please call me urgently",
    "Please pay 5000 rupees to kumar@ybl for antivirus license",
    "Send money to account 1234567890123 IFSC SBIN0001234 State Bank of India",
    "Or you can call me at +919876543210 for immediate help, also email me at scammer@hotmail.com",
    "Visit http://malware-download.xyz/install?token=abc123 and download the fix, my other number is 8527419630",
]

history = []
results = []
for msg in messages:
    result = post_process(msg, history)
    results.append(result)
    history.append({"sender": "scammer", "text": msg, "timestamp": "2026-02-10"})
    history.append({"sender": "agent", "text": result.get("reply", ""), "timestamp": "2026-02-10"})

# Score the LAST /process response (what evaluator likely uses)
last_process = results[-1]
print("=== SCORING LAST /process RESPONSE ===")
proc_score, proc_details = evaluate_final_output(last_process)
print(f"Score: {proc_score}/100")
for k, v in proc_details.items():
    max_pts = {"scamDetection": 20, "intelligenceExtraction": 40, "engagementQuality": 20, "responseStructure": 20}
    status = "OK" if v >= max_pts[k] else "MISSING"
    print(f"  {k}: {v}/{max_pts[k]} [{status}]")

# Show extracted intel
intel = last_process.get("extractedIntelligence", {})
print(f"\nExtracted Intelligence:")
for cat, items in intel.items():
    print(f"  {cat}: {items}")

metrics = last_process.get("engagementMetrics", {})
print(f"\nEngagement Metrics:")
print(f"  duration: {metrics.get('engagementDurationSeconds')}s")
print(f"  messages: {metrics.get('totalMessagesExchanged')}")

# Also score the /export response
print("\n=== SCORING /export RESPONSE ===")
req = urllib.request.Request(f"{BASE}/export/session/{SESSION}")
resp = urllib.request.urlopen(req)
export = json.loads(resp.read().decode())

exp_score, exp_details = evaluate_final_output(export)
print(f"Score: {exp_score}/100")
for k, v in exp_details.items():
    max_pts = {"scamDetection": 20, "intelligenceExtraction": 40, "engagementQuality": 20, "responseStructure": 20}
    status = "OK" if v >= max_pts[k] else "MISSING"
    print(f"  {k}: {v}/{max_pts[k]} [{status}]")

intel = export.get("extractedIntelligence", {})
print(f"\nExtracted Intelligence:")
for cat, items in intel.items():
    print(f"  {cat}: {items}")

# Final verdict
print(f"\n{'='*50}")
if proc_score >= 100 and exp_score >= 100:
    print("VERDICT: 100/100 on BOTH /process and /export")
else:
    print(f"VERDICT: /process={proc_score}, /export={exp_score}")
    if proc_score < 100:
        gaps = {k: v for k, v in proc_details.items()
                if v < {"scamDetection": 20, "intelligenceExtraction": 40, "engagementQuality": 20, "responseStructure": 20}[k]}
        print(f"  /process gaps: {gaps}")
    if exp_score < 100:
        gaps = {k: v for k, v in exp_details.items()
                if v < {"scamDetection": 20, "intelligenceExtraction": 40, "engagementQuality": 20, "responseStructure": 20}[k]}
        print(f"  /export gaps: {gaps}")
print(f"{'='*50}")

sys.exit(0 if proc_score >= 100 and exp_score >= 100 else 1)
