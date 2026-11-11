"""
ScamShield 2.0 - Stage 0: read screenshots, photos, PDFs and text files.
Turns an uploaded file into plain text that the 5-stage chain can analyse.
Needs scamshield_chain.py in the same folder.
"""

import base64
import io

from scamshield_chain import openai_client, MODEL

PROMPT_0_TRANSCRIBE = """You are Stage 0 of a scam-detection pipeline. The image is a screenshot or photo of a message (SMS, WhatsApp, email, payment request, or advertisement). Transcribe ALL visible message text exactly as written, including links, phone numbers, and amounts. Do not summarise or interpret it.
Reply with ONLY plain text in this format:
Sender: <sender name or number, or unknown>
Message: <full transcribed text>
If the image contains no readable message, reply exactly: NO_MESSAGE_FOUND"""


def extract_text_from_image(image_bytes: bytes, mime_type: str = "image/png") -> str:
    b64 = base64.b64encode(image_bytes).decode("utf-8")
    response = openai_client.responses.create(
        model=MODEL,
        input=[
            {"type": "message", "role": "system", "content": PROMPT_0_TRANSCRIBE},
            {
                "type": "message",
                "role": "user",
                "content": [
                    {"type": "input_image", "image_url": f"data:{mime_type};base64,{b64}"}
                ],
            },
        ],
    )
    return response.output_text.strip()


def extract_text_from_file(filename: str, file_bytes: bytes, mime_type: str = "") -> str:
    name = filename.lower()
    if mime_type.startswith("image/") or name.endswith((".png", ".jpg", ".jpeg", ".webp")):
        return extract_text_from_image(file_bytes, mime_type or "image/png")
    if name.endswith(".pdf"):
        from pypdf import PdfReader

        reader = PdfReader(io.BytesIO(file_bytes))
        text = "\n".join((page.extract_text() or "") for page in reader.pages).strip()
        return text or "NO_MESSAGE_FOUND"
    if name.endswith(".txt"):
        return file_bytes.decode("utf-8", errors="ignore").strip()
    raise ValueError("Unsupported file type. Use PNG, JPG, PDF, or TXT.")
