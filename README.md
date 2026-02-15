# ANCHOR - Agentic HoneyPot Engine 🛡️

**A deterministic JSON-to-JSON deception engine for scammer engagement.**

> **Anchor has no frontend UI. Interaction is via API, tests, or demo tooling only.**

---

## ⚡ Quick Start

```bash
# Install dependencies
pip install -r requirements_api.txt

# Run the API server
python anchor_api_server.py
```

The server starts on `http://localhost:8080`.

---

## Architecture

```
Input JSON (POST /process)
    │
    ▼
┌───────────────────────────────────────────────────────────────┐
│                     anchor_agent.py                           │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │ 1. Extract message from JSON                            │  │
│  │ 2. jailbreak_guard() → Block prompt injection           │  │
│  │ 3. DeterministicStateMachine.analyze_and_transition()   │  │
│  │ 4. TemplateBasedLLM.generate_response() (NO raw text!)  │  │
│  │ 5. ArtifactExtractor.extract() → UPI, bank, URLs        │  │
│  │ 6. ConversationMemory.add_*() → Store history           │  │
│  │ 7. Return structured JSON                               │  │
│  └─────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────┘
    │
    ▼
Output JSON
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/process` | Process scammer message (GUVI format) |
| POST | `/reset` | Reset session |
| GET | `/health` | Health check |

### Example Request

```bash
curl -X POST http://localhost:8080/process \
  -H "Content-Type: application/json" \
  -H "X-API-Key: anchor-secret" \
  -d '{
    "message": { "text": "Please pay to scammer@ybl" },
    "session_id": "test_01"
  }'
```

## Project Structure

```
Anchor/
├── anchor_api_server.py   # Flask HTTP API server
├── anchor_agent.py        # Main API processor
├── extractor.py           # Regex-based artifact extraction
├── memory.py              # Conversation history
├── state_machine_v2.py    # Deterministic state machine
├── llm_v2.py              # Template-based persona generation
├── config_v2.py           # Patterns, templates, settings
├── behavior_scorer.py     # Per-turn behavior scoring
├── osint_enricher.py      # OSINT artifact enrichment
├── image_parser.py        # Optional OCR for image scams
├── requirements_api.txt   # API-mode dependencies
└── test_*.py              # Test suite
```

## Running Modes

### API Server (Primary)
```bash
python anchor_api_server.py
```

### Demo Mode
```bash
python anchor_agent.py --demo
```

### Interactive Mode
```bash
python anchor_agent.py --interactive
```

## Security Features

| Rule | Implementation |
|------|----------------|
| API key enforcement | `X-API-Key` header required on all POST/GET |
| LLM never sees raw scammer text | LLM only gets state + template blanks |
| EXTRACT patterns override all states | `EXTRACT_FORCE_PATTERNS` in config |
| Jailbreak attempts force DEFLECT | `jailbreak_guard()` checked first |
| Deterministic execution | No threading, no async, no randomness in security paths |

## Dependencies

**Minimal (API mode):**
```
regex>=2023.0.0
flask>=3.0.0
python-dotenv>=0.20.0
requests>=2.31.0
```

**Optional:**
```
pytesseract + Pillow   # Image OCR
llama-cpp-python       # Enhanced LLM responses
```

## License

MIT License - Use responsibly and ethically.
