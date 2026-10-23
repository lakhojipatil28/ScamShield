"""
Screenshot Validation, Decoding, and Vision Processing Service for ScamShield.
Supports PNG, JPEG, and WebP images up to 5MB. Validates image integrity and extracts text safely.
"""

import io
import logging

from google.genai import types
from PIL import Image, UnidentifiedImageError

from backend.config import settings
from backend.services.gemini_service import gemini_service

logger = logging.getLogger("scamshield.screenshot")

ALLOWED_MIME_TYPES = {
    "image/png": "PNG",
    "image/jpeg": "JPEG",
    "image/webp": "WEBP",
}

MAX_FILE_SIZE = settings.MAX_IMAGE_SIZE_BYTES  # 5 MB


class ScreenshotService:
    def validate_image(
        self, file_bytes: bytes, declared_content_type: str | None
    ) -> tuple[bool, str, str | None]:
        """
        Validate image size, MIME type, and structural decoding integrity using Pillow.
        Returns (is_valid, error_or_success_message, detected_mime_type).
        """
        # 1. Size check
        if len(file_bytes) > MAX_FILE_SIZE:
            return (
                False,
                f"File size ({len(file_bytes) / 1024 / 1024:.2f} MB) exceeds maximum allowed limit of 5 MB",
                None,
            )

        if len(file_bytes) < 32:
            return False, "File is too small to be a valid image", None

        # 2. Decoding check with PIL
        try:
            image_buffer = io.BytesIO(file_bytes)
            with Image.open(image_buffer) as img:
                img.verify()  # Verifies file integrity and header
                format_name = img.format.upper() if img.format else ""

                if format_name == "PNG":
                    mime = "image/png"
                elif format_name in ["JPEG", "JPG"]:
                    mime = "image/jpeg"
                elif format_name == "WEBP":
                    mime = "image/webp"
                else:
                    return (
                        False,
                        f"Unsupported image format: {format_name}. Only PNG, JPEG, and WebP are allowed.",
                        None,
                    )

            return True, "Image validated successfully", mime

        except (UnidentifiedImageError, OSError, ValueError) as e:
            logger.warning(f"Image validation/decoding error: {e}")
            return False, f"Invalid or corrupted image file: {e!s}", None

    def extract_text_from_screenshot(
        self, file_bytes: bytes, mime_type: str
    ) -> tuple[str, bool, str]:
        """
        Extract text from screenshot using Gemini Multimodal Vision if available.
        Returns (extracted_text, is_ocr_confident, extraction_notes).
        """
        if not gemini_service.is_configured:
            # Fallback when Gemini API is unconfigured
            msg = (
                "[Gemini API key is unconfigured. Multimodal vision extraction requires an active GEMINI_API_KEY. "
                "Please enter the message text directly into the Text Scanner or set GEMINI_API_KEY in your .env file.]"
            )
            return (
                msg,
                False,
                "Gemini vision service not configured; automatic OCR could not be executed.",
            )

        try:
            image_part = types.Part.from_bytes(data=file_bytes, mime_type=mime_type)
            prompt = (
                "You are an accurate OCR document transcription tool for security analysis.\n"
                "Extract ALL readable text, captions, buttons, URLs, phone numbers, and sender names visible in this screenshot.\n"
                "Output ONLY the extracted transcription verbatim. Do not interpret, summarize, or critique yet."
            )

            response = gemini_service._client.models.generate_content(
                model=gemini_service.model_name,
                contents=[image_part, prompt],
                config=types.GenerateContentConfig(
                    temperature=0.0,
                    max_output_tokens=2048,
                ),
            )

            extracted = (response.text or "").strip()
            if not extracted:
                return (
                    "[No readable text found in image]",
                    False,
                    "The uploaded image appears blurry, low-resolution, or devoid of recognizable text.",
                )

            return (
                extracted,
                True,
                "Text successfully extracted via Gemini Multimodal Vision.",
            )

        except Exception as e:  # noqa: BLE001 - Vision extraction failure boundary
            logger.error(f"Error during Gemini vision extraction: {e}")
            return (
                f"[Text extraction failed: {e!s}]",
                False,
                f"Vision extraction failed due to API error: {e!s}",
            )


screenshot_service = ScreenshotService()
