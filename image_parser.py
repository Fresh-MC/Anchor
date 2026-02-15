# ANCHOR Image Parser — Optional OCR-Based Text Extraction
# =========================================================
# ARCHITECTURE RULES (STRICT):
#   1. OPTIONAL feature — system works identically without it
#   2. NEVER blocks /process response on failure
#   3. NEVER crashes — all exceptions caught, safe defaults returned
#   4. NEVER modifies extraction, state machine, or scoring logic
#   5. FULLY disabled when ANCHOR_SAFE_MODE=1
#   6. Uses pytesseract + PIL ONLY — no ML inference, no computer vision
#   7. Extracted text is appended to message.text as "[IMAGE_TEXT]: <text>"
#   8. Downstream pipeline treats image text identically to typed text
#
# DESIGN:
#   OCR-only. The extracted text feeds into the existing deterministic
#   pipeline (extractor.py → state_machine_v2.py → llm_v2.py) with
#   zero architectural changes. If OCR produces garbage or fails,
#   the system proceeds with the original message text alone.
#
# DEPENDENCIES:
#   - pytesseract (optional, pip install pytesseract)
#   - Pillow / PIL (optional, pip install Pillow)
#   - Tesseract OCR engine must be installed on the host OS
#   All are OPTIONAL. If missing, image parsing is silently skipped.

import os
import io
import base64
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# ── Lazy dependency check (never crash on import) ───────────────────────
_DEPS_AVAILABLE = False
_pytesseract = None
_Image = None

try:
    import pytesseract as _pytesseract
    from PIL import Image as _Image
    _DEPS_AVAILABLE = True
except ImportError:
    _DEPS_AVAILABLE = False


# ── SAFE MODE ───────────────────────────────────────────────────────────
def _is_safe_mode() -> bool:
    """Check if ANCHOR_SAFE_MODE is enabled."""
    return os.getenv("ANCHOR_SAFE_MODE", "0") == "1"


# ── Public API ──────────────────────────────────────────────────────────

def extract_text_from_image(image_input) -> Dict:
    """
    Extract text from an image using OCR (pytesseract + PIL).

    Args:
        image_input: One of:
            - str: base64-encoded image data
            - str: file path to an image on disk
            - bytes: raw image bytes
            - PIL.Image.Image: already-loaded PIL image
            - None: no image provided

    Returns:
        Dict with keys:
            - "text" (str): Extracted text, empty string on failure
            - "confidence" (float): 0.0–1.0, 0.0 on failure
            - "method" (str): Always "ocr"
            - "error" (Optional[str]): Error description, None on success

    GUARANTEES:
        - NEVER raises an exception
        - NEVER returns None
        - Returns safe empty result on ANY failure
        - Completes in bounded time (Tesseract default timeout)
    """
    safe_empty = {
        "text": "",
        "confidence": 0.0,
        "method": "ocr",
        "error": None,
    }

    # ── Gate 1: Safe mode → skip entirely ───────────────────────────
    if _is_safe_mode():
        safe_empty["error"] = "SAFE_MODE: image parsing disabled"
        return safe_empty

    # ── Gate 2: No input → nothing to do ────────────────────────────
    if image_input is None:
        safe_empty["error"] = "no image provided"
        return safe_empty

    # ── Gate 3: Dependencies missing → skip silently ────────────────
    if not _DEPS_AVAILABLE:
        safe_empty["error"] = "pytesseract or Pillow not installed"
        return safe_empty

    try:
        # ── Load image into PIL ─────────────────────────────────────
        pil_image = _load_image(image_input)

        if pil_image is None:
            safe_empty["error"] = "could not load image from input"
            return safe_empty

        # ── Run OCR ─────────────────────────────────────────────────
        raw_text = _pytesseract.image_to_string(pil_image)

        # Normalize whitespace
        extracted = " ".join(raw_text.split()).strip()

        if not extracted:
            safe_empty["error"] = "OCR returned empty text"
            return safe_empty

        # ── Confidence heuristic ────────────────────────────────────
        # pytesseract doesn't return a simple confidence score.
        # We use a basic heuristic: ratio of alphanumeric characters
        # to total characters. Pure noise → low ratio → low confidence.
        alnum_count = sum(1 for c in extracted if c.isalnum())
        total_count = len(extracted)
        confidence = round(alnum_count / total_count, 2) if total_count > 0 else 0.0

        # Clamp to [0.0, 1.0]
        confidence = max(0.0, min(1.0, confidence))

        return {
            "text": extracted,
            "confidence": confidence,
            "method": "ocr",
            "error": None,
        }

    except Exception as e:
        logger.warning(f"Image OCR failed (non-blocking): {e}")
        safe_empty["error"] = str(e)
        return safe_empty


# ── Internal helpers ────────────────────────────────────────────────────

def _load_image(image_input):
    """
    Attempt to load image_input into a PIL Image.
    Returns None on any failure. NEVER raises.
    """
    try:
        # Already a PIL Image
        if _Image is not None and isinstance(image_input, _Image.Image):
            return image_input

        # Raw bytes
        if isinstance(image_input, (bytes, bytearray)):
            return _Image.open(io.BytesIO(image_input))

        # String: base64 or file path
        if isinstance(image_input, str):
            # Try base64 first (most common in API payloads)
            if _looks_like_base64(image_input):
                decoded = base64.b64decode(image_input)
                return _Image.open(io.BytesIO(decoded))

            # Try as file path
            if os.path.isfile(image_input):
                return _Image.open(image_input)

            # Maybe raw base64 without padding — try anyway
            try:
                # Add padding if needed
                padded = image_input + "=" * (-len(image_input) % 4)
                decoded = base64.b64decode(padded)
                return _Image.open(io.BytesIO(decoded))
            except Exception:
                pass

        return None

    except Exception:
        return None


def _looks_like_base64(s: str) -> bool:
    """Quick heuristic: does this string look like base64 image data?"""
    if len(s) < 20:
        return False
    # Strip data URI prefix if present (e.g., "data:image/png;base64,...")
    if s.startswith("data:"):
        return ";base64," in s[:50]
    # Check if it's plausibly base64 (only valid chars)
    import re
    return bool(re.match(r'^[A-Za-z0-9+/\n\r]+=*$', s[:200]))


def deps_available() -> bool:
    """Check if OCR dependencies are installed. For diagnostics only."""
    return _DEPS_AVAILABLE
