# ANCHOR API Server - Honeypot API Evaluation System Compliant
# Fully compliant with PDF evaluation rules

"""
ANCHOR API Server - Evaluation-Compliant
=========================================
Flask-based HTTP server fully compliant with Honeypot API Evaluation System.

DESIGN:
- POST /process returns ONLY {status, reply}
- All intelligence is persisted per sessionId in-memory
- GET /export/session/<sessionId> returns the final evaluation structure
- No callbacks, no webhooks, no OSINT pushes, no background HTTP
- No randomness outside LLM reply generation
- Deterministic, side-effect-free

Endpoints:
- POST /process                     - Process scammer message
- GET  /export/session/<sessionId>  - Export final session intelligence
- POST /reset                       - Reset a session
- GET  /health                      - Health check
"""

import logging
import os
import time
import threading

try:
    from flask import Flask, request, jsonify
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

from anchor_agent import AnchorAgent, create_agent
from extractor import create_extractor
from dotenv import load_dotenv
load_dotenv()


# ═════════════════════════════════════════════════════════════════════════════
# SESSION STORE — In-memory persistence keyed by sessionId
# ═════════════════════════════════════════════════════════════════════════════

_session_store: dict = {}
_store_lock = threading.Lock()


def _get_or_create_session(session_id: str) -> dict:
    """Get existing session data or create a new one. Thread-safe."""
    with _store_lock:
        if session_id not in _session_store:
            _session_store[session_id] = {
                "session_id": session_id,
                "start_time": time.time(),
                "last_activity": time.time(),
                "total_messages": 0,
                "phone_numbers": [],
                "bank_accounts": [],
                "upi_ids": [],
                "phishing_links": [],
                "email_addresses": [],
                "crypto_wallets": [],
                "suspicious_keywords": [],
                "case_ids": [],
                "policy_numbers": [],
                "order_numbers": [],
                "generic_ids": [],
                "scam_detected": False,
                "agent_notes": "",
            }
        return _session_store[session_id]


def _update_session_intel(session_id: str, artifacts: dict, keywords: list, scam_detected: bool) -> None:
    """Merge newly extracted intelligence into the session store. Thread-safe."""
    with _store_lock:
        session = _session_store.get(session_id)
        if not session:
            return

        session["last_activity"] = time.time()
        session["total_messages"] += 1

        # Merge phone numbers (deduplicate by number string)
        existing_phones = {
            (p.get("number", p) if isinstance(p, dict) else p)
            for p in session["phone_numbers"]
        }
        for phone in artifacts.get("phone_numbers", []):
            phone_num = phone.get("number", phone) if isinstance(phone, dict) else phone
            if phone_num not in existing_phones:
                session["phone_numbers"].append(phone)
                existing_phones.add(phone_num)

        # Merge bank accounts (deduplicate by str representation)
        existing_accounts = {str(a) for a in session["bank_accounts"]}
        for acct in artifacts.get("bank_accounts", []):
            if str(acct) not in existing_accounts:
                session["bank_accounts"].append(acct)
                existing_accounts.add(str(acct))

        # Merge UPI IDs (deduplicate)
        existing_upi = set(session["upi_ids"])
        for upi in artifacts.get("upi_ids", []):
            if upi not in existing_upi:
                session["upi_ids"].append(upi)
                existing_upi.add(upi)

        # Merge phishing links (deduplicate)
        existing_links = set(session["phishing_links"])
        for link in artifacts.get("phishing_links", []):
            if link not in existing_links:
                session["phishing_links"].append(link)
                existing_links.add(link)

        # Merge email addresses (deduplicate)
        existing_emails = set(session["email_addresses"])
        for email in artifacts.get("emails", []):
            if email not in existing_emails:
                session["email_addresses"].append(email)
                existing_emails.add(email)

        # Merge suspicious keywords (deduplicate)
        existing_kw = set(session["suspicious_keywords"])
        for kw in keywords:
            if kw not in existing_kw:
                session["suspicious_keywords"].append(kw)
                existing_kw.add(kw)

        # Merge context-aware IDs (deduplicate)
        for id_key in ["case_ids", "policy_numbers", "order_numbers", "generic_ids"]:
            existing = set(session.get(id_key, []))
            for val in artifacts.get(id_key, []):
                if val not in existing:
                    session.setdefault(id_key, []).append(val)
                    existing.add(val)

        # Scam detection latches true once detected
        if scam_detected:
            session["scam_detected"] = True


def _build_export(session_id: str) -> dict:
    """Build the final evaluation-compliant export structure for a session."""
    with _store_lock:
        session = _session_store.get(session_id)

    if not session:
        return {
            "status": "completed",
            "sessionId": session_id,
            "scamDetected": False,
            "totalMessagesExchanged": 0,
            "extractedIntelligence": {
                "phoneNumbers": [],
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "emailAddresses": [],
                "caseIds": [],
                "policyNumbers": [],
                "orderNumbers": [],
                "genericIds": [],
            },
            "engagementMetrics": {
                "totalMessagesExchanged": 0,
                "engagementDurationSeconds": 0,
            },
            "agentNotes": "No session data found.",
        }

    # Count both directions: each /process call = scammer msg + agent reply
    total = session["total_messages"] * 2
    # Real elapsed time — no simulated inflation (PART 3)
    duration = int(session["last_activity"] - session["start_time"])

    # Flatten phone numbers to plain strings for export
    phone_list = []
    for p in session["phone_numbers"]:
        if isinstance(p, dict):
            phone_list.append(p.get("number", str(p)))
        else:
            phone_list.append(str(p))

    # Flatten bank accounts to plain strings/dicts for export
    bank_list = []
    for b in session["bank_accounts"]:
        if isinstance(b, dict):
            # Return the account number string or the full dict
            bank_list.append(b.get("account_number", str(b)))
        else:
            bank_list.append(str(b))

    intel_parts = []
    if phone_list:
        intel_parts.append(f"{len(phone_list)} phone(s)")
    if bank_list:
        intel_parts.append(f"{len(bank_list)} bank account(s)")
    if session["upi_ids"]:
        intel_parts.append(f"{len(session['upi_ids'])} UPI ID(s)")
    if session["phishing_links"]:
        intel_parts.append(f"{len(session['phishing_links'])} phishing link(s)")
    if session["email_addresses"]:
        intel_parts.append(f"{len(session['email_addresses'])} email(s)")
    if session.get("case_ids"):
        intel_parts.append(f"{len(session['case_ids'])} case/ref ID(s)")
    if session.get("policy_numbers"):
        intel_parts.append(f"{len(session['policy_numbers'])} policy number(s)")
    if session.get("order_numbers"):
        intel_parts.append(f"{len(session['order_numbers'])} order number(s)")

    if intel_parts:
        notes = f"Autonomous engagement completed. Extracted: {', '.join(intel_parts)}."
    elif session["scam_detected"]:
        notes = "Scam indicators detected during engagement. No extractable artifacts found."
    else:
        notes = "Engagement completed. No scam indicators detected."

    return {
        "status": "completed",
        "sessionId": session_id,
        "scamDetected": session["scam_detected"],
        "totalMessagesExchanged": total,
        "extractedIntelligence": {
            "phoneNumbers": phone_list,
            "bankAccounts": bank_list,
            "upiIds": session["upi_ids"],
            "phishingLinks": session["phishing_links"],
            "emailAddresses": session["email_addresses"],
            "caseIds": session.get("case_ids", []),
            "policyNumbers": session.get("policy_numbers", []),
            "orderNumbers": session.get("order_numbers", []),
            "genericIds": session.get("generic_ids", []),
        },
        "engagementMetrics": {
            "totalMessagesExchanged": total,
            "engagementDurationSeconds": duration,
        },
        "agentNotes": notes,
    }


# ═════════════════════════════════════════════════════════════════════════════
# SURVIVAL RESPONSES (deterministic, in-character, never silent)
# ═════════════════════════════════════════════════════════════════════════════

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


# ═════════════════════════════════════════════════════════════════════════════
# HISTORY REPLAY — Rebuild agent state from conversationHistory
# ═════════════════════════════════════════════════════════════════════════════

def rebuild_agent_from_history(agent, history):
    """
    Reconstruct memory (artifacts + scammer turn count) AND state machine context
    from conversationHistory.

    State machine replay is SAFE because:
    - analyze_and_transition is deterministic (keyword-based, no LLM)
    - It only updates internal counters (last_state, state_counts, rotation_index, scorer)

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
            artifacts = extractor.extract(text)
            if artifacts.has_artifacts():
                agent.memory.cumulative_artifacts.merge(artifacts)
            agent.memory.metrics.scammer_turns += 1
            try:
                # Compute missing intel before state transition
                missing = agent._get_missing_intel()
                agent.state_machine.set_missing_intel(missing)
                
                state, analysis = agent.state_machine.analyze_and_transition(text)
                # Advance template counter so next call won't repeat
                agent.state_machine.get_template_for_state(state, analysis)
            except Exception:
                pass
        elif sender == "agent":
            try:
                agent.state_machine.add_agent_response(text)
                # Track used responses for history-awareness
                agent.state_machine.add_used_response(text)
            except Exception:
                pass


# ═════════════════════════════════════════════════════════════════════════════
# API KEY CHECK
# ═════════════════════════════════════════════════════════════════════════════

def require_api_key():
    """Check API key and return error response if invalid."""
    api_key = request.headers.get("x-api-key")
    expected_key = os.getenv("ANCHOR_API_KEY", "anchor-secret")
    if api_key != expected_key:
        return jsonify({"status": "error", "reply": ""}), 401
    return None


# ═════════════════════════════════════════════════════════════════════════════
# FLASK APP & ROUTES
# ═════════════════════════════════════════════════════════════════════════════

if FLASK_AVAILABLE:
    app = Flask(__name__)

    # Suppress Flask logging for clean output
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    logging.getLogger('flask').setLevel(logging.ERROR)

    @app.route('/health', methods=['GET'])
    def health():
        """Health check endpoint."""
        return jsonify({
            "status": "healthy",
            "service": "ANCHOR HoneyPot API",
            "version": "3.0.0-eval-compliant",
        })

    @app.route('/process', methods=['POST'])
    def process():
        """
        Process scammer message — Evaluation-compliant.

        Accepts: sessionId, message, conversationHistory
        Returns: {status, reply, scamDetected, intelligenceFlags}

        All intelligence is persisted internally per sessionId.
        No callbacks, no OSINT, no metadata in response.
        """
        auth_error = require_api_key()
        if auth_error:
            return auth_error

        try:
            data = request.get_json()

            if not data:
                return jsonify({"status": "success", "reply": get_survival_reply()}), 200

            # ── Read sessionId from request (evaluator-provided) ──
            session_id = data.get("sessionId", "default")
            conversation_history = data.get("conversationHistory", [])

            # Extract current message text
            message_obj = data.get("message", {})
            if isinstance(message_obj, dict):
                message_text = message_obj.get("text", "")
            elif isinstance(message_obj, str):
                message_text = message_obj
            else:
                message_text = ""

            if not message_text:
                return jsonify({"status": "success", "reply": get_survival_reply()})

            # ── Ensure session exists in store ──
            _get_or_create_session(session_id)

            # ── Create agent and rebuild state from history ──
            agent = create_agent(session_id)
            rebuild_agent_from_history(agent, conversation_history)

            # ── Process current message through agent pipeline ──
            result = agent.process_api_message({
                "message": message_text,
                "session_id": session_id,
            })

            # ── Extract reply (never empty) ──
            agent_response = result.get("response", "") or get_survival_reply()

            # ── Persist intelligence into session store ──
            artifacts = agent.memory.get_all_artifacts()

            # Secondary extraction pass: run extractor directly on every
            # scammer message in history + current to catch anything missed
            scammer_texts = [
                msg.get("text", "") for msg in conversation_history
                if msg.get("sender", "").lower() == "scammer"
            ]
            scammer_texts.append(message_text)

            secondary_extractor = create_extractor()
            for stext in scammer_texts:
                if not stext:
                    continue
                extra = secondary_extractor.extract(stext)
                extra_dict = extra.to_dict() if hasattr(extra, 'to_dict') else {}
                # Merge secondary artifacts into main dict
                for key in ["phone_numbers", "bank_accounts", "upi_ids",
                            "phishing_links", "emails", "crypto_wallets",
                            "case_ids", "policy_numbers", "order_numbers",
                            "generic_ids"]:
                    existing = artifacts.get(key, [])
                    for item in extra_dict.get(key, []):
                        if item not in existing:
                            existing.append(item)
                    artifacts[key] = existing

            all_keywords = set()
            for text in scammer_texts:
                all_keywords.update(agent.extractor.extract_suspicious_keywords(text))
            suspicious_keywords = sorted(all_keywords)

            scam_detected = len(suspicious_keywords) > 0

            _update_session_intel(session_id, artifacts, suspicious_keywords, scam_detected)

            # ── Build intelligence flags from session store ──
            with _store_lock:
                session = _session_store.get(session_id, {})
                sess_scam = session.get("scam_detected", False)
                intel_flags = {
                    "phoneNumber": len(session.get("phone_numbers", [])) > 0,
                    "bankAccount": len(session.get("bank_accounts", [])) > 0,
                    "upiId": len(session.get("upi_ids", [])) > 0,
                    "phishingLink": len(session.get("phishing_links", [])) > 0,
                    "emailAddress": len(session.get("email_addresses", [])) > 0,
                    "caseId": len(session.get("case_ids", [])) > 0,
                    "policyNumber": len(session.get("policy_numbers", [])) > 0,
                    "orderNumber": len(session.get("order_numbers", [])) > 0,
                }

            # Build evaluation-compliant export fields
            eval_data = _build_export(session_id)

            engagement_metrics = eval_data.get("engagementMetrics", {
                "engagementDurationSeconds": 0, "totalMessagesExchanged": 0,
            })

            return jsonify({
                "status": "success",
                "sessionId": session_id,
                "reply": agent_response,
                "scamDetected": sess_scam,
                "intelligenceFlags": intel_flags,
                "extractedIntelligence": eval_data.get("extractedIntelligence", {
                    "phoneNumbers": [], "bankAccounts": [], "upiIds": [],
                    "phishingLinks": [], "emailAddresses": [],
                    "caseIds": [], "policyNumbers": [], "orderNumbers": [],
                    "genericIds": [],
                }),
                "engagementMetrics": engagement_metrics,
                "engagementDurationSeconds": engagement_metrics.get("engagementDurationSeconds", 0),
                "agentNotes": eval_data.get("agentNotes", "Engagement in progress."),
                "totalMessagesExchanged": eval_data.get("totalMessagesExchanged", 0),
            })

        except Exception:
            # Attempt to recover session data if any was persisted before error
            recovered = {}
            err_sid = "default"
            try:
                raw = request.get_json(silent=True) or {}
                err_sid = raw.get("sessionId", "default")
                recovered = _build_export(err_sid)
            except Exception:
                pass

            recovered_metrics = recovered.get("engagementMetrics", {
                "engagementDurationSeconds": 0,
                "totalMessagesExchanged": 0,
            })

            return jsonify({
                "status": "success",
                "sessionId": err_sid,
                "reply": get_survival_reply(),
                "scamDetected": recovered.get("scamDetected", False),
                "intelligenceFlags": {
                    "phoneNumber": len(recovered.get("extractedIntelligence", {}).get("phoneNumbers", [])) > 0,
                    "bankAccount": len(recovered.get("extractedIntelligence", {}).get("bankAccounts", [])) > 0,
                    "upiId": len(recovered.get("extractedIntelligence", {}).get("upiIds", [])) > 0,
                    "phishingLink": len(recovered.get("extractedIntelligence", {}).get("phishingLinks", [])) > 0,
                    "emailAddress": len(recovered.get("extractedIntelligence", {}).get("emailAddresses", [])) > 0,
                    "caseId": len(recovered.get("extractedIntelligence", {}).get("caseIds", [])) > 0,
                    "policyNumber": len(recovered.get("extractedIntelligence", {}).get("policyNumbers", [])) > 0,
                    "orderNumber": len(recovered.get("extractedIntelligence", {}).get("orderNumbers", [])) > 0,
                },
                "extractedIntelligence": recovered.get("extractedIntelligence", {
                    "phoneNumbers": [],
                    "bankAccounts": [],
                    "upiIds": [],
                    "phishingLinks": [],
                    "emailAddresses": [],
                    "caseIds": [],
                    "policyNumbers": [],
                    "orderNumbers": [],
                    "genericIds": [],
                }),
                "engagementMetrics": recovered_metrics,
                "engagementDurationSeconds": recovered_metrics.get("engagementDurationSeconds", 0),
                "agentNotes": recovered.get("agentNotes", "Error during processing. Engagement maintained."),
                "totalMessagesExchanged": recovered.get("totalMessagesExchanged", 0),
            })

    @app.route('/export/session/<session_id>', methods=['GET'])
    def export_session(session_id):
        """
        Export final session intelligence — Evaluation-compliant.

        Returns the exact JSON structure required by the evaluator.
        No side effects, no background processing.
        """
        return jsonify(_build_export(session_id))

    @app.route('/reset', methods=['POST'])
    def reset():
        """Reset a session — clears all stored intelligence."""
        auth_error = require_api_key()
        if auth_error:
            return auth_error

        try:
            data = request.get_json() or {}
            session_id = data.get("sessionId", data.get("session_id", "default"))

            with _store_lock:
                _session_store.pop(session_id, None)

            return jsonify({"status": "success"})
        except Exception:
            return jsonify({"status": "success"})

    @app.route('/sessions', methods=['GET'])
    def list_sessions():
        """List all tracked session IDs."""
        auth_error = require_api_key()
        if auth_error:
            return auth_error

        with _store_lock:
            session_ids = list(_session_store.keys())

        return jsonify({
            "status": "success",
            "sessions": session_ids,
            "count": len(session_ids),
        })


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

    print(f"ANCHOR HoneyPot API (Eval-Compliant) running on http://{host}:{port}")
    app.run(host=host, port=port, debug=debug, use_reloader=False)


if __name__ == "__main__":
    import sys

    port = int(os.getenv("PORT", "8080"))
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass

    run_server(port=port, debug=False)
