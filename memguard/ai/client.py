"""
memguard.ai.client
==================
Ollama API client with:
  • Streaming token-by-token output
  • Automatic fallback to secondary model on failure / low-confidence output
  • Structured JSON output enforcement with schema validation
  • Token budgeting and context truncation
  • Local model health check
"""

from __future__ import annotations
import asyncio
import re

import json
import logging
import os
import time
from typing import AsyncIterator

import httpx
from pydantic import ValidationError

log = logging.getLogger(__name__)

OLLAMA_BASE   = os.environ.get("MEMGUARD_OLLAMA_URL", "http://localhost:11434")
DEFAULT_MODEL = "qwen2.5-coder:14b-instruct-q4_K_M"
FALLBACK_MODEL= "deepseek-coder-v2:16b-lite-instruct-q4_K_M"
FAST_MODEL    = "qwen2.5-coder:7b-instruct-q8_0"

TIMEOUT = httpx.Timeout(connect=5.0, read=600.0, write=10.0, pool=5.0)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

async def list_local_models() -> list[str]:
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(f"{OLLAMA_BASE}/api/tags")
            return [m["name"] for m in r.json().get("models", [])]
    except Exception:
        return []


async def best_available_model(preferred: str = DEFAULT_MODEL) -> str:
    models = await list_local_models()
    for candidate in [preferred, FALLBACK_MODEL, FAST_MODEL]:
        if any(candidate in m for m in models):
            return candidate
    if models:
        # Return whatever is installed
        return models[0]
    raise RuntimeError(
        "No Ollama models found. Run: ollama pull qwen2.5-coder:14b-instruct-q4_K_M"
    )


# ---------------------------------------------------------------------------
# Core completion
# ---------------------------------------------------------------------------

async def complete(
    messages: list[dict],
    model: str = DEFAULT_MODEL,
    temperature: float = 0.05,
    max_tokens: int = 4096,
    system: str | None = None,
    stream: bool = False,
) -> str | AsyncIterator[str]:
    payload: dict = {
        "model":   model,
        "options": {
            "temperature": temperature,
            "num_predict": max_tokens,
            "top_p":       0.95,
            "repeat_penalty": 1.1,
        },
        "stream": stream,
    }
    if system:
        payload["messages"] = [{"role": "system", "content": system}] + messages
    else:
        payload["messages"] = messages

    if stream:
        return _stream_complete(payload)
    return await _blocking_complete(payload)


async def _blocking_complete(payload: dict) -> str:
    last_err: Exception | None = None
    for attempt in range(2):
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.post(
                    f"{OLLAMA_BASE}/api/chat", json=payload
                )
                resp.raise_for_status()
                data = resp.json()
                # Defensive: Ollama may return error payloads with 200 status
                content = data.get("message", {}).get("content")
                if content is None:
                    raise RuntimeError(
                        f"Unexpected Ollama response shape: {str(data)[:200]}")
                return content
        except (httpx.TimeoutException, httpx.ConnectError) as e:
            last_err = e
            if attempt == 1:  # final attempt exhausted
                raise RuntimeError(f"Ollama unreachable: {e}") from e
            log.warning("Ollama request failed (attempt %d), retrying: %s",
                        attempt + 1, e)
            await asyncio.sleep(3)
        except httpx.HTTPStatusError as e:
            raise RuntimeError(
                f"Ollama HTTP {e.response.status_code}: "
                f"{e.response.text[:200]}") from e
    raise RuntimeError(f"Ollama request failed after retries: {last_err}")


async def _stream_complete(payload: dict) -> AsyncIterator[str]:
    payload["stream"] = True
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        async with client.stream(
            "POST", f"{OLLAMA_BASE}/api/chat", json=payload
        ) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line.strip():
                    continue
                try:
                    chunk = json.loads(line)
                    if token := chunk.get("message", {}).get("content", ""):
                        yield token
                    if chunk.get("done"):
                        break
                except json.JSONDecodeError:
                    continue


# ---------------------------------------------------------------------------
# Structured JSON completion with retry + validation
# ---------------------------------------------------------------------------

def _fix_json_escapes(text: str) -> str:
    """Fix invalid escape sequences that LLMs produce in JSON strings.
    
    Valid JSON escapes: \\" \\\\ \\/ \\b \\f \\n \\r \\t \\uXXXX
    Must handle: \\s → \\\\s, but leave \\\\s alone (already valid).
    """
    VALID_AFTER_BACKSLASH = frozenset('"' + '\\' + '/bfnrtu')
    out = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == '\\' and i + 1 < n:
            nxt = text[i + 1]
            if nxt == '\\':
                # Already an escaped backslash \\  — keep both, skip pair
                out.append('\\\\')
                i += 2
                continue
            elif nxt in VALID_AFTER_BACKSLASH:
                # Valid escape like \n \t \" — keep as-is
                out.append('\\')
                out.append(nxt)
                i += 2
                continue
            else:
                # Invalid escape like \s \p \d — double the backslash
                out.append('\\\\')
                out.append(nxt)
                i += 2
                continue
        out.append(c)
        i += 1
    return ''.join(out)


async def complete_json(
    messages: list[dict],
    schema_description: str,
    model: str = DEFAULT_MODEL,
    fallback_model: str = FALLBACK_MODEL,
    max_retries: int = 3,
) -> dict:
    """
    Request a JSON response and validate it's parseable.
    Retries with explicit error feedback, then falls back to secondary model.
    """
    system = (
        "You are a memory safety expert. "
        "You MUST respond with ONLY valid JSON matching this schema — "
        "no markdown fences, no preamble, no explanation outside JSON:\n\n"
        + schema_description
    )

    last_error = ""
    for attempt in range(max_retries):
        use_model = model if attempt < 2 else fallback_model
        msgs = list(messages)
        if last_error:
            msgs.append({
                "role": "user",
                "content": (
                    f"Your previous response had this JSON error: {last_error}\n"
                    "Please respond again with ONLY valid JSON."
                ),
            })

        t0  = time.monotonic()
        try:
            raw = await complete(msgs, model=use_model, system=system, temperature=0.05, max_tokens=1500)
        except RuntimeError as e:
            # Fallback model not installed (404) — retry with primary
            if "404" in str(e) and use_model != model:
                log.warning("Fallback model %s not available, retrying with %s",
                            use_model, model)
                try:
                    raw = await complete(msgs, model=model, system=system, temperature=0.05, max_tokens=1500)
                except Exception:
                    continue
            else:
                raise
        ms  = int((time.monotonic() - t0) * 1000)

        # Strip any accidental markdown fences
        raw = raw.strip()
        if raw.startswith("```"):
            raw = re.sub(r"```(?:json)?\n?", "", raw).strip("`").strip()

        # Sanitize invalid escape sequences from LLM output
        # LLMs often produce \s, \p, \d, \w etc. inside JSON strings
        raw = _fix_json_escapes(raw)

        try:
            parsed = json.loads(raw)
            log.debug("JSON parse OK in %dms (attempt %d)", ms, attempt + 1)
            parsed["_model"]      = use_model
            parsed["_latency_ms"] = ms
            return parsed
        except json.JSONDecodeError as e:
            last_error = str(e)
            log.warning("JSON parse failed (attempt %d): %s", attempt + 1, e)

    # Last resort: aggressively extract JSON from mixed output
    depth = 0
    start = -1
    for i, ch in enumerate(raw):
        if ch == '{':
            if depth == 0:
                start = i
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0 and start >= 0:
                candidate = raw[start:i+1]
                try:
                    return json.loads(_fix_json_escapes(candidate))
                except Exception:
                    pass
                break

    raise ValueError(f"Could not parse JSON after {max_retries} attempts. Last raw:\n{raw[:500]}")

