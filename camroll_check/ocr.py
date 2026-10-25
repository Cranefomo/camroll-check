"""OCR backends. On a Mac, Apple Vision (via ocrmac) is used when installed:
it is the same engine iOS uses for Live Text. Everywhere else, Tesseract."""
from __future__ import annotations

import os

from PIL import Image

try:  # HEIC support for iPhone photos
    import pillow_heif  # type: ignore
    pillow_heif.register_heif_opener()
    HEIC = True
except Exception:
    HEIC = False

try:
    from ocrmac import ocrmac  # type: ignore
    BACKEND = "apple-vision"
except Exception:
    ocrmac = None
    BACKEND = "tesseract"


def open_image(path: str) -> Image.Image:
    img = Image.open(path)
    img.load()
    return img.convert("RGB")


def read_text(path: str) -> str:
    if ocrmac is not None:
        lines = ocrmac.OCR(path).recognize()
        return "\n".join(t for t, _conf, _box in lines)
    import pytesseract
    img = open_image(path)
    # small screenshots OCR better upscaled
    if img.width < 1000:
        k = 1000 / img.width
        img = img.resize((1000, int(img.height * k)))
    return pytesseract.image_to_string(img, lang=os.environ.get("CAMROLL_LANG", "eng"))
