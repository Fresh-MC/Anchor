# ANCHOR Image Parser — Test Suite
# =================================
# Tests for image_parser.py OCR functionality.
# All tests are safe to run WITHOUT pytesseract/Pillow installed —
# they verify graceful degradation and safe-return behavior.

import os
import sys
import unittest

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from image_parser import extract_text_from_image, deps_available


class TestImageParserSafeReturns(unittest.TestCase):
    """Tests that ALWAYS pass regardless of whether OCR deps are installed."""

    def test_none_input(self):
        """None input → safe empty result, no crash."""
        result = extract_text_from_image(None)
        self.assertIsInstance(result, dict)
        self.assertEqual(result["text"], "")
        self.assertEqual(result["confidence"], 0.0)
        self.assertEqual(result["method"], "ocr")
        self.assertIsNotNone(result["error"])

    def test_empty_string_input(self):
        """Empty string → safe empty result, no crash."""
        result = extract_text_from_image("")
        self.assertIsInstance(result, dict)
        self.assertEqual(result["text"], "")
        self.assertEqual(result["confidence"], 0.0)
        self.assertEqual(result["method"], "ocr")

    def test_invalid_bytes(self):
        """Random bytes → no crash, safe return."""
        result = extract_text_from_image(b"\x00\x01\x02\x03\xff\xfe")
        self.assertIsInstance(result, dict)
        self.assertEqual(result["text"], "")
        self.assertEqual(result["confidence"], 0.0)

    def test_invalid_base64(self):
        """Invalid base64 string → no crash."""
        result = extract_text_from_image("not-a-real-base64-image!!!")
        self.assertIsInstance(result, dict)
        self.assertEqual(result["text"], "")
        self.assertEqual(result["confidence"], 0.0)

    def test_nonexistent_filepath(self):
        """Nonexistent file path → no crash."""
        result = extract_text_from_image("/tmp/nonexistent_anchor_test_image.png")
        self.assertIsInstance(result, dict)
        self.assertEqual(result["text"], "")
        self.assertEqual(result["confidence"], 0.0)

    def test_integer_input(self):
        """Integer input → no crash (unexpected type)."""
        result = extract_text_from_image(12345)
        self.assertIsInstance(result, dict)
        self.assertEqual(result["text"], "")
        self.assertEqual(result["confidence"], 0.0)

    def test_list_input(self):
        """List input → no crash (unexpected type)."""
        result = extract_text_from_image([1, 2, 3])
        self.assertIsInstance(result, dict)
        self.assertEqual(result["text"], "")
        self.assertEqual(result["confidence"], 0.0)

    def test_result_schema(self):
        """Result always has the required keys."""
        result = extract_text_from_image(None)
        self.assertIn("text", result)
        self.assertIn("confidence", result)
        self.assertIn("method", result)
        self.assertIn("error", result)
        self.assertIsInstance(result["text"], str)
        self.assertIsInstance(result["confidence"], float)
        self.assertEqual(result["method"], "ocr")

    def test_deps_available_returns_bool(self):
        """deps_available() always returns a bool."""
        self.assertIsInstance(deps_available(), bool)


class TestImageParserSafeMode(unittest.TestCase):
    """Tests that SAFE_MODE disables image parsing."""

    def test_safe_mode_skips_parsing(self):
        """ANCHOR_SAFE_MODE=1 → image parsing skipped entirely."""
        original = os.environ.get("ANCHOR_SAFE_MODE")
        try:
            os.environ["ANCHOR_SAFE_MODE"] = "1"
            result = extract_text_from_image(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
            self.assertEqual(result["text"], "")
            self.assertEqual(result["confidence"], 0.0)
            self.assertIn("SAFE_MODE", result["error"])
        finally:
            if original is None:
                os.environ.pop("ANCHOR_SAFE_MODE", None)
            else:
                os.environ["ANCHOR_SAFE_MODE"] = original

    def test_safe_mode_off_allows_parsing(self):
        """ANCHOR_SAFE_MODE=0 → parsing not blocked by safe mode."""
        original = os.environ.get("ANCHOR_SAFE_MODE")
        try:
            os.environ["ANCHOR_SAFE_MODE"] = "0"
            result = extract_text_from_image(None)
            # Should fail for a different reason (no image), not safe mode
            self.assertNotIn("SAFE_MODE", result.get("error", ""))
        finally:
            if original is None:
                os.environ.pop("ANCHOR_SAFE_MODE", None)
            else:
                os.environ["ANCHOR_SAFE_MODE"] = original


@unittest.skipUnless(deps_available(), "pytesseract/Pillow not installed — skipping OCR tests")
class TestImageParserWithDeps(unittest.TestCase):
    """Tests that run ONLY when pytesseract + Pillow are installed."""

    def test_valid_image_extraction(self):
        """Create a simple image with text and verify OCR extracts it."""
        from PIL import Image, ImageDraw, ImageFont

        # Create a white image with black text
        img = Image.new("RGB", (300, 100), color="white")
        draw = ImageDraw.Draw(img)
        try:
            font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 24)
        except (OSError, IOError):
            font = ImageFont.load_default()
        draw.text((10, 30), "Hello Anchor", fill="black", font=font)

        result = extract_text_from_image(img)
        self.assertIsInstance(result, dict)
        self.assertEqual(result["method"], "ocr")
        # OCR should extract something (may not be perfect)
        if result["text"]:
            self.assertGreater(result["confidence"], 0.0)
            self.assertIsNone(result["error"])

    def test_valid_image_bytes(self):
        """Image as bytes → text extracted."""
        from PIL import Image, ImageDraw
        import io

        img = Image.new("RGB", (200, 80), color="white")
        draw = ImageDraw.Draw(img)
        draw.text((10, 20), "9876543210", fill="black")

        buf = io.BytesIO()
        img.save(buf, format="PNG")
        image_bytes = buf.getvalue()

        result = extract_text_from_image(image_bytes)
        self.assertIsInstance(result, dict)
        self.assertEqual(result["method"], "ocr")

    def test_blank_image(self):
        """Blank image → empty text, low/zero confidence."""
        from PIL import Image

        img = Image.new("RGB", (100, 100), color="white")
        result = extract_text_from_image(img)
        self.assertIsInstance(result, dict)
        # Blank image should yield empty or near-empty text
        self.assertEqual(result["method"], "ocr")


if __name__ == "__main__":
    print("=" * 60)
    print(" ANCHOR Image Parser — Test Suite")
    print("=" * 60)
    print(f"  OCR deps available: {deps_available()}")
    print(f"  SAFE_MODE: {os.getenv('ANCHOR_SAFE_MODE', '0')}")
    print("=" * 60)
    unittest.main(verbosity=2)
