import json
import logging
import re
import urllib.request
from typing import Dict, Optional
from playwright.async_api import Page

from ahvf_crawler.config import LlmConfig

logger = logging.getLogger("ahvf_crawler.llm")

DISTILL_DOM_JS = """
() => {
    // Clone the body so we don't destroy the actual page
    const clone = document.body.cloneNode(true);
    
    // Remove noisy elements
    const noisyTags = ['script', 'style', 'svg', 'path', 'meta', 'link', 'noscript', 'iframe'];
    noisyTags.forEach(tag => {
        const elements = clone.querySelectorAll(tag);
        elements.forEach(el => el.remove());
    });
    
    // Remove comments
    const iterator = document.createNodeIterator(clone, NodeFilter.SHOW_COMMENT, () => NodeFilter.FILTER_ACCEPT);
    let currentNode;
    const comments = [];
    while (currentNode = iterator.nextNode()) {
        comments.push(currentNode);
    }
    comments.forEach(c => c.remove());
    
    // Optionally remove hidden elements
    // We approximate this by removing elements with inline display:none
    const allElems = clone.querySelectorAll('*');
    allElems.forEach(el => {
        if (el.style && el.style.display === 'none') {
            el.remove();
        }
    });

    // Reduce deep nesting of divs that contain only divs
    // This is optional but helps with React/Vue soup
    
    // Minify whitespace
    let html = clone.innerHTML;
    html = html.replace(/\s+/g, ' ');
    html = html.replace(/> </g, '><');
    
    return html.trim();
}
"""

SYSTEM_PROMPT = """You are a DOM analysis assistant. Your only job is to identify 
form fields on a login page and return a structured JSON object.
Return ONLY valid JSON. No explanation, no markdown, no preamble.

USER:
Analyze this login page DOM snapshot and identify all interactive 
fields required to authenticate.

Return a JSON object with this exact structure:
{
  "login_type": "form | sso | mfa | unknown",
  "fields": [
    {
      "purpose": "username | password | otp | captcha | remember_me | other",
      "label": "human-readable label shown on page",
      "selector": "best CSS selector to target this element",
      "selector_fallbacks": ["alternative selectors in priority order"],
      "input_type": "text | password | email | tel | number | checkbox",
      "required": true | false,
      "prompt_user": "exact question to ask the operator for this field's value",
      "safe_to_autofill": true | false
    }
  ],
  "submit": {
    "selector": "CSS selector for the submit button",
    "selector_fallbacks": ["alternatives"]
  },
  "sso_options": [
    { "provider": "Google", "selector": "..." }
  ],
  "notes": "anything unusual about this login page"
}

Selector priority rules:
1. Prefer data-testid or data-cy attributes (most stable)
2. Then id attribute
3. Then name attribute on input
4. Then aria-label
5. Then type + placeholder combination
6. Last resort: positional nth-child selector

DOM SNAPSHOT:
"""

async def distill_dom(page: Page) -> str:
    """Extract a minified, noise-free representation of the DOM."""
    try:
        html = await page.evaluate(DISTILL_DOM_JS)
        # Limit the size just in case it's still massive (e.g. 15k chars)
        return html[:15000]
    except Exception as e:
        logger.error(f"Failed to distill DOM: {e}")
        return ""

def analyze_login_page(config: LlmConfig, distilled_html: str) -> Optional[Dict]:
    """Send distilled DOM to LLM and parse the resulting JSON."""
    if not distilled_html:
        return None
        
    full_prompt = SYSTEM_PROMPT + f"\n{distilled_html}\n"
    
    payload = {
        "model": config.model,
        "prompt": full_prompt,
        "stream": False,
        "options": {
            "temperature": 0.0,
            "num_predict": 1000
        }
    }
    
    req = urllib.request.Request(
        config.api_url, 
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    
    logger.info(f"Submitting DOM snapshot to LLM ({config.model})...")
    
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            resp_data = json.loads(response.read().decode())
            raw_answer = resp_data.get("response", "")
            
            # Extract JSON block
            json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', raw_answer, re.DOTALL | re.IGNORECASE)
            if json_match:
                json_str = json_match.group(1)
            else:
                # Try to parse the raw string directly in case the LLM followed instructions perfectly
                # (no markdown wrapper)
                json_str = raw_answer.strip()
                # Find first { and last }
                start = json_str.find('{')
                end = json_str.rfind('}')
                if start != -1 and end != -1:
                    json_str = json_str[start:end+1]
                
            try:
                parsed = json.loads(json_str)
                return parsed
            except json.JSONDecodeError as e:
                logger.error(f"Failed to decode JSON from LLM: {e}\nRaw Answer: {raw_answer[:200]}...")
                return None
                
    except Exception as e:
        logger.error(f"LLM request failed: {e}")
        return None
