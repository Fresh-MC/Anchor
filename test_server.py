"""Quick test: start server + hit it with a request."""
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
# Health check
try:
    req = urllib.request.Request("http://127.0.0.1:5055/health")
    resp = urllib.request.urlopen(req)
    print(f"HEALTH: {resp.read().decode()}", flush=True)
except Exception as e:
    print(f"HEALTH FAILED: {e}", flush=True)

# Process test
try:
    body = json.dumps({
        "sessionId": "test-1",
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
    print(f"STATUS: {result.get('status')}", flush=True)
    print(f"REPLY: {result.get('reply')}", flush=True)
except Exception as e:
    print(f"PROCESS FAILED: {e}", flush=True)

print("TEST DONE", flush=True)
