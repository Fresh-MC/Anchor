# ANCHOR API Server - GUVI Agentic HoneyPot API Specification
# Production-ready HTTP server for hackathon submission (STATELESS)

"""
ANCHOR API Server - GUVI HoneyPot Compliant (Stateless)
========================================================
Flask-based HTTP server compliant with GUVI Agentic HoneyPot API specification.

STATELESS DESIGN:
- Each request creates a fresh agent
- conversationHistory is used to reconstruct state
- No reliance on server-side memory persistence

Endpoints:
- POST /process     - Process scammer message (GUVI format)
- POST /reset       - Reset session (no-op in stateless mode)
- GET  /health      - Health check

Request Format:
{
    "sessionId": "<session identifier>",
    "message": {
        "text": "<scammer message>",
        "sender": "<sender id>",
        "timestamp": "<ISO timestamp>"
    },
    "conversationHistory": [
        {"sender": "scammer", "text": "...", "timestamp": ...},
        {"sender": "agent", "text": "...", "timestamp": ...},
        ...
    ],
    "metadata": {...}
}

Response Format:
{
    "status": "success",
    "reply": "<agent response>"
}
"""

import logging
import os
import time
import threading
import uuid
import requests

try:
    from flask import Flask, request, jsonify
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False


from anchor_agent import AnchorAgent, create_agent
from extractor import create_extractor
from osint_enricher import get_enricher as get_osint_enricher
from image_parser import extract_text_from_image
from observer_server import observer_bp, init_observer_db, store_event
from dotenv import load_dotenv
load_dotenv()

# ── SAFE MODE ────────────────────────────────────────────────────────────
SAFE_MODE = os.getenv("ANCHOR_SAFE_MODE", "0") == "1"

# ── SESSION REGISTRY ─────────────────────────────────────────────────────
# In-memory map: client_id → {"session_id": str, "last_seen": float}
# Backend is the SINGLE source of truth for session identity.
# Same client within 15 min → same session. After 15 min gap → new session.
SESSION_TIMEOUT = int(os.getenv("ANCHOR_SESSION_TIMEOUT", "900"))  # seconds
_session_registry: dict[str, dict] = {}
_registry_lock = threading.Lock()


def resolve_session(client_id: str) -> str:
    """
    Return the active session_id for client_id.
    Creates a new session if the client is unknown or timed out (>15 min).
    Thread-safe.
    """
    now = time.time()
    with _registry_lock:
        entry = _session_registry.get(client_id)
        if entry and (now - entry["last_seen"]) <= SESSION_TIMEOUT:
            entry["last_seen"] = now
            return entry["session_id"]
        # New or timed-out client → fresh session
        new_session = str(uuid.uuid4())
        _session_registry[client_id] = {"session_id": new_session, "last_seen": now}
        return new_session

# ── OBSERVER (passive, fire-and-forget, in-process) ─────────────────────
# Writes go directly to SQLite via store_event() — no HTTP round-trip.
# A daemon thread is used so the INSERT never blocks /process.
# Any failure is silently swallowed.


def write_observer_event(session_id: str, payload: dict) -> None:
    """
    Fire-and-forget write to SQLite via observer_server.store_event().
    Runs in a daemon thread so it can never block /process.
    Silently swallows all exceptions — observer is non-critical.
    Skipped entirely when SAFE_MODE is active.
    """
    if SAFE_MODE:
        return

    def _store():
        try:
            store_event(payload)
        except Exception:
            pass  # observer failure is NEVER visible to Anchor

    threading.Thread(target=_store, daemon=True).start()

# ── SURVIVAL RESPONSES (deterministic, in-character, never silent) ──────
SURVIVAL_RESPONSES = [
    "Hello? Is someone there? The line is very bad.",
    "I'm sorry, I couldn't hear that. Can you say it again?",
    "One moment dear, I need to adjust my hearing aid.",
    "Hmm, the phone is making strange noises. Are you still there?",
    "I think we got disconnected for a second. What were you saying?",
]
_survival_counter = 0

def get_survival_reply() -> str:
    """Deterministic in-character fallback. NEVER returns empty."""
    global _survival_counter
    reply = SURVIVAL_RESPONSES[_survival_counter % len(SURVIVAL_RESPONSES)]
    _survival_counter += 1
    return reply


# Track sessions: session_id -> intel_count at last callback
_session_last_intel = {}

# GUVI Final Result Endpoint
GUVI_FINAL_RESULT_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

def rebuild_agent_from_history(agent, history):
    """
    Reconstruct memory (artifacts + scammer turn count) AND state machine context
    from GUVI conversationHistory.
    
    State machine replay is SAFE because:
    - analyze_and_transition is deterministic (keyword-based, no LLM)
    - It only updates internal counters (last_state, state_counts, rotation_index, scorer)
    - Without replay, the state machine starts blank every request and always returns CLARIFY
    
    We reconstruct:
    1. Cumulative artifacts (from scammer messages)
    2. Scammer turn count
    3. State machine context (via replay of scammer + agent messages)
    """
    extractor = create_extractor()
    
    # Reset memory AND state machine for clean replay
    agent.memory.reset()
    agent.state_machine.reset()
    
    for msg in history:
        text = msg.get("text", "")
        sender = msg.get("sender", "").lower()
        
        if not text:
            continue
        
        if sender == "scammer":
            # 1. Extract artifacts from historical scammer message
            artifacts = extractor.extract(text)
            
            # 2. Merge artifacts into cumulative store
            if artifacts.has_artifacts():
                agent.memory.cumulative_artifacts.merge(artifacts)
            
            # 3. Increment scammer turn count
            agent.memory.metrics.scammer_turns += 1
            
            # 4. Replay through state machine so it builds context
            #    (updates last_state, state_counts, scorer, rotation_index)
            try:
                agent.state_machine.analyze_and_transition(text)
            except Exception:
                pass  # state machine replay failure is non-critical
        
        elif sender == "agent":
            # Record agent response so state machine tracks conversation flow
            try:
                agent.state_machine.add_agent_response(text)
            except Exception:
                pass


def count_scammer_turns(conversation_history: list) -> int:
    """Count number of scammer messages in history"""
    return sum(1 for msg in conversation_history if msg.get("sender", "").lower() == "scammer")


def send_final_callback(session_id: str, agent, scam_detected: bool, suspicious_keywords: list):
    """
    Submit final intelligence to GUVI endpoint.
    Called when intelligence is extracted and turns >= 3.
    In SAFE_MODE, logs but does NOT make the HTTP call.
    """
    try:
        artifacts = agent.memory.get_all_artifacts()
        total_turns = agent.memory.metrics.scammer_turns
        behavior = agent.state_machine.scorer.get_summary()
        
        intelligence = {
            "bankAccounts": artifacts.get("bank_accounts", []),
            "upiIds": artifacts.get("upi_ids", []),
            "phishingLinks": artifacts.get("phishing_links", []),
            "phoneNumbers": artifacts.get("phone_numbers", []),
            "suspiciousKeywords": suspicious_keywords
        }
        
        payload = {
            "sessionId": session_id,
            "scamDetected": scam_detected,
            "totalMessagesExchanged": total_turns,
            "extractedIntelligence": intelligence,
            "behaviorScore": behavior["cumulative_score"],
            "agentNotes": "Autonomous engagement completed. Intelligence extracted via deception."
        }
        
        print(f"\n🔔 CALLBACK TRIGGERED: Session {session_id}")
        print(f"   Turns: {total_turns}")
        print(f"   Behavior Score: {behavior['cumulative_score']}")
        print(f"   UPI IDs: {len(intelligence['upiIds'])}")
        print(f"   Bank Accounts: {len(intelligence['bankAccounts'])}")
        print(f"   Phishing Links: {len(intelligence['phishingLinks'])}")
        print(f"   Phone Numbers: {len(intelligence['phoneNumbers'])}")
        
        if SAFE_MODE:
            print("   🛡️ SAFE_MODE: callback logged, HTTP skipped")
            return
        
        response = requests.post(
            GUVI_FINAL_RESULT_URL,
            json=payload,
            timeout=5
        )
        print(f"   GUVI Response: {response.status_code}")
        
    except Exception as e:
        print(f"   ⚠️ Callback error: {str(e)}")


def require_api_key():
    """Check API key and return error response if invalid"""
    api_key = request.headers.get("x-api-key")
    expected_key = os.getenv("ANCHOR_API_KEY", "anchor-secret")
    
    if api_key != expected_key:
        return jsonify({"status": "error", "reply": ""}), 401
    return None


if FLASK_AVAILABLE:
    app = Flask(__name__)

    # ── Mount observer blueprint (public-read, no API key) ──────────────
    app.register_blueprint(observer_bp, url_prefix="/observer")
    init_observer_db()
    
    # Suppress all Flask logging for clean output
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    logging.getLogger('flask').setLevel(logging.ERROR)
    
    @app.route('/health', methods=['GET'])
    def health():
        """Health check endpoint"""
        return jsonify({
            "status": "healthy",
            "service": "ANCHOR HoneyPot API",
            "version": "2.2.0-deterministic",
            "safe_mode": SAFE_MODE,
        })
    
    @app.route('/process', methods=['POST'])
    def process():
        """
        Process scammer message - GUVI HoneyPot API compliant (STATELESS).
        
        Reconstructs BOTH memory AND state machine from conversationHistory
        without replaying messages through the agent.
        """
        auth_error = require_api_key()
        if auth_error:
            return auth_error
        
        try:
            data = request.get_json()
            
            if not data:
                return jsonify({"status": "success", "reply": get_survival_reply()}), 200
            
            # ── Resolve client identity ──────────────────────────────────
            # Priority: X-Client-ID header → anchor_client_id cookie → new uuid4
            client_id = (
                request.headers.get("X-Client-ID")
                or request.cookies.get("anchor_client_id")
                or str(uuid.uuid4())
            )
            
            # ── Server-side session resolution (ignore frontend sessionId) ──
            session_id = resolve_session(client_id)
            conversation_history = data.get("conversationHistory", [])
            
            # Extract current message
            message_obj = data.get("message", {})
            message_text = message_obj.get("text", "") if isinstance(message_obj, dict) else ""
            
            # ── Optional image OCR (non-blocking, safe-mode aware) ──
            # If message.image exists, attempt OCR and append to text.
            # On ANY failure, proceeds with original text only.
            if isinstance(message_obj, dict) and message_obj.get("image"):
                try:
                    ocr_result = extract_text_from_image(message_obj["image"])
                    if ocr_result.get("text"):
                        image_text = ocr_result["text"].strip()
                        if image_text:
                            if message_text:
                                message_text = message_text + " [IMAGE_TEXT]: " + image_text
                            else:
                                message_text = "[IMAGE_TEXT]: " + image_text
                except Exception:
                    pass  # Image parsing failure is NEVER visible to the caller
            
            if not message_text:
                return jsonify({"status": "success", "reply": get_survival_reply()})
            
            # STATELESS: Create fresh agent for this request
            agent = create_agent(session_id)
            
            # Rebuild memory AND state machine from history (no LLM calls)
            rebuild_agent_from_history(agent, conversation_history)
            
            # Process ONLY the current message through the agent
            result = agent.process_api_message({
                "message": message_text,
                "session_id": session_id
            })
            
            # Extract response
            agent_response = result.get("response", "") or get_survival_reply()
            
            # ✅ Read cumulative state from memory, not result
            artifacts = agent.memory.get_all_artifacts()
            turns = agent.memory.metrics.scammer_turns
            
            # ── OSINT: Fire-and-forget post-extraction enrichment ──
            # GUARANTEES:
            #   - Returns in < 0.1ms (daemon thread dispatch only)
            #   - NEVER blocks the /process response
            #   - NEVER mutates artifacts dict
            #   - Fully disabled in SAFE_MODE
            try:
                osint_enricher = get_osint_enricher()
                osint_enricher.enrich_async(
                    session_id=session_id,
                    artifacts_dict=artifacts,
                    skip_holehe=True,  # Holehe is slow — offline/post-incident only
                )
            except Exception:
                pass  # OSINT failure is NEVER visible to the caller
            
            # ── Scam Detection + Keyword Extraction (all scammer messages) ──
            scammer_texts = [
                msg.get("text", "") for msg in conversation_history
                if msg.get("sender", "").lower() == "scammer"
            ]
            scammer_texts.append(message_text)
            
            all_keywords = set()
            for text in scammer_texts:
                all_keywords.update(agent.extractor.extract_suspicious_keywords(text))
            suspicious_keywords = sorted(all_keywords)
            
            # Scam detected if any suspicious keywords found (latches via history)
            scam_detected = len(suspicious_keywords) > 0
            
            # ── Callback: fire when turns >= 8 and new intel available ──
            intel_count = (
                len(artifacts.get("upi_ids", [])) +
                len(artifacts.get("bank_accounts", [])) +
                len(artifacts.get("phishing_links", [])) +
                len(artifacts.get("phone_numbers", [])) +
                len(suspicious_keywords)
            )
            has_intel = intel_count > 0
            last_count = _session_last_intel.get(session_id, 0)
            
            if has_intel and turns >= 3 and intel_count > last_count:
                send_final_callback(session_id, agent, scam_detected, suspicious_keywords)
                _session_last_intel[session_id] = intel_count
            
            # ── OSINT: poll for results (may still be pending) ────────
            try:
                osint_data = osint_enricher.get_results(session_id)
            except Exception:
                osint_data = {}

            # ── Behavior scores from state machine scorer ───────────────
            try:
                behavior_summary = agent.state_machine.scorer.get_summary()
                behavior_scores = {
                    "urgency": behavior_summary.get("latest_score", 0.0),
                    "pressure": behavior_summary.get("cumulative_score", 0.0),
                    "aggregate": behavior_summary.get("cumulative_score", 0.0),
                    "session_behavior_score": behavior_summary.get("session_behavior_score", 0.0),
                    "escalation_multiplier": behavior_summary.get("escalation_multiplier", 0.0),
                    "dimensions_fired": behavior_summary.get("dimensions_fired", []),
                    "per_turn": behavior_summary.get("per_turn", []),
                }
            except Exception:
                behavior_scores = {
                    "urgency": 0, "pressure": 0, "aggregate": 0,
                    "session_behavior_score": 0.0, "escalation_multiplier": 0.0,
                    "dimensions_fired": [], "per_turn": [],
                }

            # ── OSINT verdict ────────────────────────────────────────────
            try:
                osint_verdict = osint_data.get("osint_verdict", "unknown_no_prior_intel") if osint_data else "unknown_no_prior_intel"
            except Exception:
                osint_verdict = "unknown_no_prior_intel"

            # ── Build final response (DO NOT modify after this point) ────
            response_json = {
                "status": "success",
                "reply": agent_response,
                "response": agent_response,
                "state": result.get("state", "CLARIFY"),
                "behavior_scores": behavior_scores,
                "extracted_artifacts": artifacts,
                "osint_enrichment": osint_data,
                "osint_verdict": osint_verdict,
                "turn_index": turns,
                "session_id": session_id,
                "metadata": result.get("metadata", {}),
            }

            # ── OBSERVER: mirror a copy AFTER response is finalized ──────
            # This runs in a daemon thread and cannot affect the response.
            # Schema is fixed — dashboard depends on this shape.
            try:
                observer_payload = {
                    "session_id": session_id,
                    "timestamp": int(time.time() * 1000),  # epoch ms — dashboard expects ms
                    "turn_index": turns,
                    "state": result.get("state", "CLARIFY"),
                    "behavior_score": float(behavior_scores.get("aggregate", 0.0)),
                    "session_behavior_score": float(behavior_scores.get("session_behavior_score", 0.0)),
                    "escalation_multiplier": float(behavior_scores.get("escalation_multiplier", 0.0)),
                    "osint_verdict": osint_verdict,
                    "artifacts": dict(artifacts) if artifacts else {},
                    "osint": dict(osint_data) if osint_data else {},
                    "response": agent_response,
                }
                write_observer_event(session_id, observer_payload)
            except Exception:
                pass  # observer must never interfere with /process

            # Return FULL intelligence response (GUVI reply + forensic data)
            resp = jsonify(response_json)
            # ── Persist client identity via secure cookie ────────────────
            resp.set_cookie(
                "anchor_client_id",
                client_id,
                max_age=60 * 60 * 24 * 30,  # 30 days
                httponly=True,
                samesite="Lax",
            )
            return resp
            
        except Exception:
            # SURVIVAL: Never silent – always in-character
            return jsonify({"status": "success", "reply": get_survival_reply()})
    
    @app.route('/reset', methods=['POST'])
    def reset():
        """Reset session - clears callback tracking"""
        auth_error = require_api_key()
        if auth_error:
            return auth_error
        
        try:
            data = request.get_json() or {}
            session_id = data.get("sessionId", data.get("session_id", "default"))
            
            # Clear callback tracking to allow new callback
            _session_last_intel.pop(session_id, None)
            
            return jsonify({"status": "success"})
                
        except Exception:
            return jsonify({"status": "success"})
    
    @app.route('/osint/<session_id>', methods=['GET'])
    def get_osint(session_id):
        """Poll OSINT enrichment results for a session (async updates)."""
        auth_error = require_api_key()
        if auth_error:
            return auth_error
        try:
            enricher = get_osint_enricher()
            results = enricher.get_results(session_id)
            return jsonify({"status": "success", "osint_enrichment": results})
        except Exception:
            return jsonify({"status": "success", "osint_enrichment": {}})

    @app.route('/sessions', methods=['GET'])
    def list_sessions():
        """List completed sessions"""
        auth_error = require_api_key()
        if auth_error:
            return auth_error
        
        return jsonify({
            "status": "success",
            "completed_callbacks": len(_session_last_intel)
        })


# Change this line in anchor_api_server.py
def run_server(host: str = "0.0.0.0", port: int = 8080, debug: bool = False):
    """
    Run ANCHOR API server.
    
    Args:
        host: Bind address
        port: Port number
        debug: Enable debug mode
    """
    if not FLASK_AVAILABLE:
        print("ERROR: Flask not installed. Run: pip install flask")
        return
    
    print(f"ANCHOR HoneyPot API (Stateless) running on http://{host}:{port}")
    
    app.run(host=host, port=port, debug=debug, use_reloader=False)


if __name__ == "__main__":
    import sys
    
    port = 8080
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    
    run_server(port=port, debug=False)
