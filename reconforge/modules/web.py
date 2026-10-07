"""HTTP reconnaissance helpers."""

from __future__ import annotations

from urllib.parse import urljoin

import httpx


def fetch_web(url: str, timeout: int = 10, user_agent: str = "ReconForge/0.1") -> dict:
    """Fetch a URL and collect basic HTTP and security metadata."""
    try:
        with httpx.Client(follow_redirects=True, timeout=timeout, headers={"User-Agent": user_agent}) as client:
            response = client.get(url)
            redirect_chain = [str(item) for item in getattr(response, "history", [])]
            headers = {k: v for k, v in response.headers.items()}
            return {
                "ok": True,
                "url": str(response.url),
                "status_code": response.status_code,
                "server": headers.get("server", "Unknown"),
                "content_type": headers.get("content-type", "Unknown"),
                "redirect_chain": redirect_chain,
                "headers": headers,
                "response_time": getattr(response, "elapsed", None),
                "cookies": list(response.cookies.keys()),
                "security_headers": {
                    "content-security-policy": headers.get("content-security-policy"),
                    "strict-transport-security": headers.get("strict-transport-security"),
                    "x-frame-options": headers.get("x-frame-options"),
                    "x-content-type-options": headers.get("x-content-type-options"),
                    "referrer-policy": headers.get("referrer-policy"),
                },
            }
    except httpx.HTTPError as exc:
        return {"ok": False, "message": f"Web request failed: {exc}", "status_code": None}


def check_file(url: str, path: str, timeout: int = 8, user_agent: str = "ReconForge/0.1") -> bool:
    """Check whether a standard file such as robots.txt is available."""
    target = urljoin(url.rstrip("/") + "/", path)
    try:
        with httpx.Client(timeout=timeout, headers={"User-Agent": user_agent}) as client:
            response = client.get(target, follow_redirects=True)
            return response.status_code in {200, 204, 403}
    except httpx.HTTPError:
        return False
