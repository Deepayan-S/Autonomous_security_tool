"""
AHVF — Ollama Client Wrapper
==============================
Reusable client for all communication with the local Ollama instance.
Every AHVF module that needs LLM inference uses this — never calls
Ollama directly.

Supports:
  - Health check (verify Ollama is running + model is available)
  - Single text generation
  - JSON-mode generation with validation and retry
  - Batch generation (for FR-05.1 schema batching)
  - Configurable model, host, and timeouts

Configuration (env-var overrides with defaults):
  OLLAMA_HOST  = http://localhost:11434   (Ollama API base URL)
  OLLAMA_MODEL = goekdenizguelmez/JOSIEFIED-Qwen3:8b
  OLLAMA_TIMEOUT = 300                   (seconds per request)

Design note: Uses the Ollama REST API directly via `requests` rather
than the `ollama` Python package, to minimise external dependencies
and maintain full control over request/response handling.

USAGE:
    from ollama_client import OllamaClient

    client = OllamaClient()
    client.health_check()            # raises if Ollama is down
    result = client.generate("system prompt", "user prompt")
    json_result = client.generate_json("system prompt", "user prompt")
"""

import json
import os
import time
from typing import Optional


# ─────────────────────────────────────────────
#  CONFIGURATION (env-var overrides)
# ─────────────────────────────────────────────

DEFAULT_HOST    = "http://localhost:11434"
DEFAULT_MODEL   = "goekdenizguelmez/JOSIEFIED-Qwen3:8b"
DEFAULT_TIMEOUT = 300  # seconds — local models can be slow on first load


# ─────────────────────────────────────────────
#  EXCEPTIONS
# ─────────────────────────────────────────────

class OllamaError(Exception):
    """Base exception for Ollama client errors."""
    pass


class OllamaConnectionError(OllamaError):
    """Ollama server is not reachable."""
    pass


class OllamaModelNotFoundError(OllamaError):
    """Requested model is not available in Ollama."""
    pass


class OllamaGenerationError(OllamaError):
    """LLM generation failed."""
    pass


class OllamaJSONParseError(OllamaError):
    """LLM response was not valid JSON."""
    pass


# ─────────────────────────────────────────────
#  CLIENT CLASS
# ─────────────────────────────────────────────

class OllamaClient:
    """
    Client for the local Ollama REST API.

    Handles connection management, generation requests,
    JSON mode, and structured error handling.

    The client is designed to be instantiated once and reused
    across a pipeline run. Call close() or use as context manager
    to clean up the requests session.
    """

    def __init__(
        self,
        host: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[int] = None,
    ):
        self.host = host or os.environ.get("OLLAMA_HOST", DEFAULT_HOST)
        self.model = model or os.environ.get("OLLAMA_MODEL", DEFAULT_MODEL)
        self.timeout = timeout or int(os.environ.get("OLLAMA_TIMEOUT", str(DEFAULT_TIMEOUT)))

        # Strip trailing slash from host
        self.host = self.host.rstrip("/")

        # Lazy-import requests to keep module importable without it
        import requests as _requests
        self._session = _requests.Session()
        self._requests = _requests

        print(f"[Ollama] Client configured: host={self.host}, model={self.model}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        """Close the HTTP session."""
        if self._session:
            self._session.close()
            self._session = None
            print("[Ollama] Session closed")

    # ── Health Check ─────────────────────────────────────────────

    def health_check(self) -> dict:
        """
        Verify Ollama is running and the configured model is available.

        Returns a dict with:
          - server_ok: bool
          - model_available: bool
          - model_name: str
          - models_list: list of available model names

        Raises OllamaConnectionError if server is unreachable.
        Raises OllamaModelNotFoundError if model is not pulled.
        """
        # Step 1: Check server is alive
        try:
            resp = self._session.get(f"{self.host}/api/tags", timeout=10)
            resp.raise_for_status()
        except self._requests.ConnectionError:
            raise OllamaConnectionError(
                f"Cannot connect to Ollama at {self.host}. "
                "Is Ollama running? Start it with: ollama serve"
            )
        except self._requests.RequestException as e:
            raise OllamaConnectionError(f"Ollama health check failed: {e}")

        # Step 2: Check model availability
        try:
            data = resp.json()
            models = [m.get("name", "") for m in data.get("models", [])]
        except (ValueError, KeyError):
            models = []

        # Ollama model names can include tag — match flexibly
        model_available = any(
            self.model in m or m.startswith(self.model.split(":")[0])
            for m in models
        )

        if not model_available:
            raise OllamaModelNotFoundError(
                f"Model '{self.model}' not found in Ollama. "
                f"Available models: {models}. "
                f"Pull it with: ollama pull {self.model}"
            )

        result = {
            "server_ok": True,
            "model_available": model_available,
            "model_name": self.model,
            "models_list": models,
        }
        print(f"[Ollama] Health check passed: {self.model} is available")
        return result

    # ── Text Generation ──────────────────────────────────────────

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.7,
        max_retries: int = 2,
    ) -> str:
        """
        Generate a text completion from the local LLM.

        Uses the /api/chat endpoint (chat-style with system + user messages)
        for better instruction following compared to raw /api/generate.

        Returns the raw text response from the model.
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
            },
        }

        for attempt in range(max_retries + 1):
            try:
                resp = self._session.post(
                    f"{self.host}/api/chat",
                    json=payload,
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                data = resp.json()

                # Extract the assistant's response
                content = data.get("message", {}).get("content", "")
                if not content:
                    raise OllamaGenerationError("Empty response from model")

                return content

            except self._requests.ConnectionError:
                raise OllamaConnectionError(
                    f"Lost connection to Ollama at {self.host} during generation"
                )
            except self._requests.Timeout:
                if attempt < max_retries:
                    wait = (attempt + 1) * 10
                    print(f"[Ollama] Timeout on attempt {attempt + 1}, retrying in {wait}s...")
                    time.sleep(wait)
                    continue
                raise OllamaGenerationError(
                    f"Generation timed out after {self.timeout}s "
                    f"({max_retries + 1} attempts)"
                )
            except self._requests.RequestException as e:
                if attempt < max_retries:
                    wait = (attempt + 1) * 5
                    print(f"[Ollama] Request error on attempt {attempt + 1}: {e}, retrying in {wait}s...")
                    time.sleep(wait)
                    continue
                raise OllamaGenerationError(f"Generation failed: {e}")

    # ── JSON Generation ──────────────────────────────────────────

    def generate_json(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.3,
        max_retries: int = 3,
    ) -> list | dict:
        """
        Generate a JSON completion from the local LLM.

        Uses Ollama's native JSON format mode for more reliable
        structured output. Falls back to manual JSON extraction
        if the model doesn't support format mode.

        Lower temperature (0.3) for more deterministic JSON output.

        Returns parsed JSON (dict or list).
        Raises OllamaJSONParseError if all retries fail to produce valid JSON.
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "format": "json",  # Ollama native JSON mode
            "options": {
                "temperature": temperature,
            },
        }

        last_error = None

        for attempt in range(max_retries + 1):
            try:
                resp = self._session.post(
                    f"{self.host}/api/chat",
                    json=payload,
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                data = resp.json()

                content = data.get("message", {}).get("content", "")
                if not content:
                    raise OllamaGenerationError("Empty response from model")

                # Attempt to parse JSON
                parsed = self._extract_json(content)
                return parsed

            except self._requests.ConnectionError:
                raise OllamaConnectionError(
                    f"Lost connection to Ollama at {self.host}"
                )
            except (OllamaJSONParseError, OllamaGenerationError) as e:
                last_error = e
                if attempt < max_retries:
                    print(
                        f"[Ollama] JSON parse failed on attempt {attempt + 1}: {e}. "
                        f"Retrying ({max_retries - attempt} left)..."
                    )
                    # On retry without JSON mode in case the model doesn't support it
                    if attempt == 1:
                        payload.pop("format", None)
                        print("[Ollama] Retrying without JSON format mode")
                    continue
            except self._requests.RequestException as e:
                last_error = e
                if attempt < max_retries:
                    wait = (attempt + 1) * 5
                    print(f"[Ollama] Request error: {e}, retrying in {wait}s...")
                    time.sleep(wait)
                    continue

        raise OllamaJSONParseError(
            f"Failed to get valid JSON after {max_retries + 1} attempts. "
            f"Last error: {last_error}"
        )

    # ── Batch Generation ─────────────────────────────────────────

    def generate_batch(
        self,
        system_prompt: str,
        user_prompts: list[str],
        json_mode: bool = True,
        batch_size: int = 50,
    ) -> list:
        """
        Process multiple prompts in sequence (FR-05.1).

        Ollama doesn't support true batch API, so we send prompts
        one at a time. The batch_size parameter controls how many
        schemas are included in each prompt (not how many API calls).

        If json_mode is True, uses generate_json for each prompt.
        Otherwise, uses generate for raw text.

        Returns a list of results (one per prompt).
        """
        results = []
        total = len(user_prompts)

        for i, prompt in enumerate(user_prompts, 1):
            print(f"[Ollama] Processing batch {i}/{total}...")
            start = time.time()

            try:
                if json_mode:
                    result = self.generate_json(system_prompt, prompt)
                else:
                    result = self.generate(system_prompt, prompt)
                results.append(result)
            except OllamaError as e:
                print(f"[Ollama] Batch item {i} failed: {e}")
                results.append(None)  # Placeholder — caller handles None

            elapsed = time.time() - start
            print(f"[Ollama] Batch {i}/{total} done in {elapsed:.1f}s")

        return results

    # ── Internal Helpers ─────────────────────────────────────────

    @staticmethod
    def _extract_json(text: str) -> list | dict:
        """
        Extract and parse JSON from LLM output.

        Handles common LLM quirks:
          - JSON wrapped in markdown code fences (```json ... ```)
          - Leading/trailing whitespace and text
          - JSON embedded in explanatory text
        """
        cleaned = text.strip()

        # Remove markdown code fences if present
        if cleaned.startswith("```"):
            # Strip opening fence (```json or ```)
            first_newline = cleaned.index("\n") if "\n" in cleaned else len(cleaned)
            cleaned = cleaned[first_newline + 1:]
            # Strip closing fence
            if cleaned.rstrip().endswith("```"):
                cleaned = cleaned.rstrip()[:-3].rstrip()

        # Try direct parse first
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass

        # Try to find JSON array or object in the text
        for start_char, end_char in [("[", "]"), ("{", "}")]:
            start_idx = cleaned.find(start_char)
            end_idx = cleaned.rfind(end_char)
            if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                candidate = cleaned[start_idx:end_idx + 1]
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    continue

        raise OllamaJSONParseError(
            f"Could not extract valid JSON from response: {text[:200]}..."
        )


# ─────────────────────────────────────────────
#  STANDALONE TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("\n=== Ollama Client Test ===\n")

    client = OllamaClient()

    try:
        info = client.health_check()
        print(f"Server OK: {info['server_ok']}")
        print(f"Model:     {info['model_name']}")
        print(f"Available: {info['models_list']}")

        # Quick generation test
        print("\n--- Text Generation Test ---")
        resp = client.generate(
            system_prompt="You are a helpful assistant. Reply in one sentence.",
            user_prompt="What is SQL injection?",
        )
        print(f"Response: {resp}")

        # JSON generation test
        print("\n--- JSON Generation Test ---")
        resp_json = client.generate_json(
            system_prompt="You are a JSON-only responder. Return valid JSON only.",
            user_prompt='Return a JSON object with keys "name" and "type" describing SQL injection.',
        )
        print(f"JSON Response: {json.dumps(resp_json, indent=2)}")

    except OllamaError as e:
        print(f"ERROR: {e}")
    finally:
        client.close()
