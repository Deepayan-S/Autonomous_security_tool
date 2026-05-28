import base64
import json
import re
import cv2
import numpy as np
import urllib.request
import logging
from typing import Optional, Tuple
from playwright.async_api import Page, Locator

from ahvf_crawler.config import CaptchaConfig
import ahvf_crawler.db as db

logger = logging.getLogger("ahvf_crawler.captcha")

CAPTCHA_SELECTORS = {
    "image_text": ["img[src*='captcha']", "img[id*='captcha']", ".captcha-image"],
    "image_math": ["img[src*='math']"],  # Often overlaps with image_text
    "image_grid": [".recaptcha", ".h-captcha", "iframe[src*='recaptcha']"],
    "slider": [".geetest", ".slider-captcha"],
}

async def detect_captcha(page: Page) -> Optional[Tuple[Locator, str]]:
    """Scan DOM for known CAPTCHA signatures."""
    for c_type, selectors in CAPTCHA_SELECTORS.items():
        for sel in selectors:
            try:
                loc = page.locator(sel).first
                if await loc.is_visible(timeout=500):
                    return loc, c_type
            except Exception:
                pass
    return None

async def capture_captcha(page: Page, loc: Locator) -> bytes:
    """Capture CAPTCHA via element screenshot or canvas export."""
    tag_name = await loc.evaluate("el => el.tagName.toLowerCase()")
    if tag_name == "canvas":
        data_url = await loc.evaluate("el => el.toDataURL('image/png')")
        header, encoded = data_url.split(",", 1)
        return base64.b64decode(encoded)
    else:
        return await loc.screenshot(type="png")

def preprocess_captcha(image_bytes: bytes) -> bytes:
    """
    OpenCV pipeline: 
    - flatten transparency
    - upscale if width < 150
    - grayscale
    - fastNlMeansDenoising
    - adaptive threshold binarization
    - morphological closing
    """
    nparr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_UNCHANGED)

    if img is None:
        return image_bytes

    # Flatten transparency
    if len(img.shape) == 3 and img.shape[2] == 4:
        alpha_channel = img[:, :, 3]
        rgb_channels = img[:, :, :3]
        white_background = np.ones_like(rgb_channels, dtype=np.uint8) * 255
        alpha_factor = alpha_channel[:, :, np.newaxis] / 255.0
        img = (rgb_channels * alpha_factor + white_background * (1 - alpha_factor)).astype(np.uint8)
    
    # Upscale
    h, w = img.shape[:2]
    if w < 150:
        scale = 150.0 / w
        img = cv2.resize(img, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)

    # Grayscale
    if len(img.shape) == 3:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    else:
        gray = img
        
    # Denoise
    denoised = cv2.fastNlMeansDenoising(gray, None, h=10, templateWindowSize=7, searchWindowSize=21)
    
    # Adaptive threshold
    thresh = cv2.adaptiveThreshold(denoised, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2)
    
    # Morphological closing
    kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (3, 3))
    closed = cv2.morphologyEx(thresh, cv2.MORPH_CLOSE, kernel)
    
    _, encoded = cv2.imencode('.png', closed)
    return encoded.tobytes()

def solve_with_ollama(config: CaptchaConfig, base64_img: str, c_type: str) -> Tuple[str, str]:
    """Submit to local Ollama and parse."""
    prompt = "Solve this CAPTCHA. Reply with ONLY the text or math result."
    
    payload = {
        "model": config.model,
        "prompt": prompt,
        "images": [base64_img],
        "stream": False,
        "options": {
            "temperature": 0.0,
            "num_predict": 20
        }
    }
    
    req = urllib.request.Request(
        config.api_url, 
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            resp_data = json.loads(response.read().decode())
            raw_answer = resp_data.get("response", "")
            
            # Parse based on type
            clean = raw_answer.strip()
            if c_type == "image_math":
                m = re.search(r'\d+', clean)
                return raw_answer, (m.group(0) if m else clean)
            else:
                clean = re.sub(r'[^a-zA-Z0-9]', '', clean)
                return raw_answer, clean
    except Exception as e:
        logger.error(f"Ollama request failed: {e}")
        return str(e), ""

async def handle_captcha(page: Page, config: CaptchaConfig, role: str, db_path: str) -> bool:
    """
    Main flow: detect, process, submit to LLM, solve. 
    Returns True if CAPTCHA solved or none found, False if max retries exceeded.
    """
    if not config.enabled:
        return True

    for attempt in range(config.max_retries):
        detection = await detect_captcha(page)
        if not detection:
            return True # No CAPTCHA found/visible
            
        loc, c_type = detection
        logger.info(f"[{role}] CAPTCHA detected ({c_type}), attempt {attempt+1}/{config.max_retries}")
        
        try:
            raw_bytes = await capture_captcha(page, loc)
            proc_bytes = preprocess_captcha(raw_bytes)
            
            raw_b64 = base64.b64encode(raw_bytes).decode('utf-8')
            proc_b64 = base64.b64encode(proc_bytes).decode('utf-8')
            
            # Save to DB
            c_record = {
                "role": role,
                "url": page.url,
                "captcha_type": c_type,
                "raw_image_b64": raw_b64,
                "preprocessed_image_b64": proc_b64,
                "metadata": {"attempt": attempt + 1}
            }
            c_id = await db.save_captcha(db_path, c_record)
            
            raw_ans, clean_ans = solve_with_ollama(config, proc_b64, c_type)
            
            status = "solved" if clean_ans else "failed"
            await db.update_captcha_solve(db_path, c_id, status, raw_ans, clean_ans)
            
            if clean_ans:
                # Attempt to fill standard captcha inputs
                captcha_inputs = ["input[name*='captcha']", "input[id*='captcha']", ".captcha-input"]
                for c_in in captcha_inputs:
                    try:
                        inp = page.locator(c_in).first
                        if await inp.is_visible(timeout=1000):
                            await inp.fill(clean_ans)
                            break
                    except Exception:
                        pass
                        
                # Let dom.py handle the form submission after this returns True
                return True

        except Exception as e:
            logger.error(f"[{role}] CAPTCHA handling error: {e}")
            
    logger.warning(f"[{role}] CAPTCHA_BLOCK - max retries exceeded.")
    return False
