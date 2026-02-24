"""
OWASP ZAP Tool Wrapper

Controls ZAP proxy for spidering + active scanning of deployed applications.
Expects ZAP to be running (e.g., via Docker).

Handles Docker networking: when ZAP runs in Docker, it can't reach
'localhost' on the host machine. This module translates URLs automatically.
"""

from __future__ import annotations

import logging
import time
from urllib.parse import urlparse, urlunparse

import httpx

from loopsec.core.config import get_config
from loopsec.core.models import Finding, FindingSource, Severity

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "0": Severity.INFO,      # Informational
    "1": Severity.LOW,
    "2": Severity.MEDIUM,
    "3": Severity.HIGH,
}

# Confidence threshold — skip low-confidence results
MIN_CONFIDENCE = 1  # 0=false positive, 1=low, 2=medium, 3=high

# Well-known Docker Compose service names → localhost port mappings
# Used to auto-detect if a URL points to a Docker service
DOCKER_SERVICE_PORTS = {
    "vuln-app": 5001,
    "juice-shop": 3000,
    "dvwa": 8081,
}


def _translate_url_for_zap(url: str) -> str:
    """
    Translate a localhost URL to one ZAP (in Docker) can reach.

    localhost:5001  → vuln-app:5001   (Docker service name)
    localhost:3000  → juice-shop:3000
    127.0.0.1:5001  → vuln-app:5001

    If no known service matches, falls back to host.docker.internal.
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port

    if host not in ("localhost", "127.0.0.1"):
        return url  # Already a remote/Docker URL, no translation needed

    # Try to match port to a known Docker service
    for service_name, service_port in DOCKER_SERVICE_PORTS.items():
        if port == service_port:
            new_netloc = f"{service_name}:{port}"
            translated = urlunparse(parsed._replace(netloc=new_netloc))
            logger.info(f"ZAP URL translation: {url} → {translated}")
            return translated

    # Fallback: use host.docker.internal (works on Mac & Windows Docker)
    new_netloc = f"host.docker.internal:{port}" if port else "host.docker.internal"
    translated = urlunparse(parsed._replace(netloc=new_netloc))
    logger.info(f"ZAP URL translation (fallback): {url} → {translated}")
    return translated


def _translate_url_from_zap(url: str, original_target: str) -> str:
    """
    Translate a ZAP-internal URL back to the user-facing URL.

    vuln-app:5001/api/login → localhost:5001/api/login
    """
    orig_parsed = urlparse(original_target)
    orig_host = f"{orig_parsed.hostname}:{orig_parsed.port}" if orig_parsed.port else orig_parsed.hostname

    for service_name in DOCKER_SERVICE_PORTS:
        if service_name in url:
            return url.replace(
                f"{service_name}:{DOCKER_SERVICE_PORTS[service_name]}",
                orig_host or "localhost"
            ).replace(service_name, orig_host or "localhost")

    if "host.docker.internal" in url:
        return url.replace("host.docker.internal", orig_parsed.hostname or "localhost")

    return url


class ZAPClient:
    """Client for the ZAP REST API with retry logic."""

    MAX_RETRIES = 3
    RETRY_DELAY = 5  # seconds between retries

    def __init__(self, host: str | None = None, api_key: str | None = None):
        cfg = get_config().tools
        self.host = (host or cfg.zap_host).rstrip("/")
        self.api_key = api_key or cfg.zap_api_key
        self.client = httpx.Client(timeout=60)  # Generous timeout for active scans

    def _get(self, path: str, params: dict | None = None) -> dict:
        """Make a GET request to ZAP API with retries."""
        params = params or {}
        if self.api_key:
            params["apikey"] = self.api_key
        url = f"{self.host}{path}"

        last_error = None
        for attempt in range(self.MAX_RETRIES):
            try:
                resp = self.client.get(url, params=params)
                resp.raise_for_status()
                return resp.json()
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout) as e:
                last_error = e
                if attempt < self.MAX_RETRIES - 1:
                    logger.warning(
                        f"ZAP API request failed (attempt {attempt + 1}/{self.MAX_RETRIES}): {e}"
                    )
                    time.sleep(self.RETRY_DELAY)
                    # Recreate client in case connection pool is stale
                    self.client = httpx.Client(timeout=60)

        raise last_error  # type: ignore[misc]

    def is_running(self) -> bool:
        try:
            self._get("/JSON/core/view/version/")
            return True
        except Exception:
            return False

    def spider(self, target_url: str, max_duration: int = 120) -> None:
        """Spider (crawl) the target application."""
        logger.info(f"ZAP spidering {target_url}")
        resp = self._get("/JSON/spider/action/scan/", {"url": target_url, "maxDuration": str(max_duration)})
        scan_id = resp.get("scan", "0")

        while True:
            try:
                status = self._get("/JSON/spider/view/status/", {"scanId": scan_id})
                progress = int(status.get("status", "100"))
                if progress >= 100:
                    break
                logger.debug(f"Spider progress: {progress}%")
            except Exception as e:
                logger.warning(f"Spider status check failed: {e}")
            time.sleep(3)

        logger.info("Spider complete")

    def active_scan(self, target_url: str, max_duration: int = 300) -> None:
        """Run ZAP active scanner against the target."""
        logger.info(f"ZAP active scanning {target_url}")
        resp = self._get("/JSON/ascan/action/scan/", {"url": target_url})
        scan_id = resp.get("scan", "0")

        consecutive_failures = 0
        start = time.time()
        while time.time() - start < max_duration:
            try:
                status = self._get("/JSON/ascan/view/status/", {"scanId": scan_id})
                progress = int(status.get("status", "100"))
                consecutive_failures = 0  # Reset on success
                if progress >= 100:
                    break
                logger.debug(f"Active scan progress: {progress}%")
            except Exception as e:
                consecutive_failures += 1
                logger.warning(
                    f"Active scan status check failed ({consecutive_failures}): {e}"
                )
                # If ZAP has been unresponsive for too long, bail out gracefully
                if consecutive_failures >= 5:
                    logger.error("ZAP unresponsive after 5 consecutive failures, stopping scan")
                    break
            time.sleep(5)

        logger.info("Active scan complete")

    def get_alerts(self, target_url: str = "") -> list[dict]:
        """Retrieve all alerts from ZAP."""
        params: dict[str, str] = {"start": "0", "count": "500"}
        if target_url:
            params["baseurl"] = target_url
        try:
            resp = self._get("/JSON/alert/view/alerts/", params)
            return resp.get("alerts", [])
        except Exception as e:
            logger.error(f"Failed to retrieve ZAP alerts: {e}")
            return []

    def clear_session(self) -> None:
        """Clear ZAP session for a fresh start."""
        try:
            self._get("/JSON/core/action/newSession/", {"overwrite": "true"})
        except Exception as e:
            logger.warning(f"Failed to clear ZAP session: {e}")


def run_zap_scan(target_url: str) -> list[Finding]:
    """
    Full ZAP pipeline: spider → active scan → collect alerts.

    Handles Docker networking automatically — translates localhost URLs
    to Docker-internal URLs so ZAP can reach the target.

    Args:
        target_url: URL of the deployed application (user-facing, e.g. localhost:5001)

    Returns:
        List of Finding objects
    """
    zap = ZAPClient()

    if not zap.is_running():
        logger.warning("ZAP is not running. Skipping ZAP scan.")
        return []

    # Translate URL for ZAP inside Docker
    zap_url = _translate_url_for_zap(target_url)

    # Verify ZAP can actually reach the target
    if not _verify_target_reachable(zap, zap_url):
        # Try host.docker.internal fallback
        parsed = urlparse(target_url)
        port = parsed.port or 80
        fallback_url = f"{parsed.scheme}://host.docker.internal:{port}"
        logger.info(f"Primary URL unreachable, trying fallback: {fallback_url}")
        if _verify_target_reachable(zap, fallback_url):
            zap_url = fallback_url
        else:
            logger.error(f"ZAP cannot reach target at {zap_url} or {fallback_url}")
            return []

    logger.info(f"ZAP scanning: {zap_url} (original: {target_url})")

    zap.clear_session()
    zap.spider(zap_url)
    zap.active_scan(zap_url)
    alerts = zap.get_alerts(zap_url)

    return _parse_alerts(alerts, original_target=target_url)


def _verify_target_reachable(zap: ZAPClient, url: str) -> bool:
    """Ask ZAP to access the URL to verify it can reach the target."""
    try:
        zap._get("/JSON/core/action/accessUrl/", {"url": url, "followRedirects": "true"})
        return True
    except Exception as e:
        logger.debug(f"ZAP cannot reach {url}: {e}")
        return False


def _parse_alerts(alerts: list[dict], original_target: str = "") -> list[Finding]:
    """Convert ZAP alerts to Finding objects, translating Docker URLs back."""
    findings: list[Finding] = []
    seen = set()  # Dedup by (alert, url, param)

    for alert in alerts:
        confidence = int(alert.get("confidence", "0"))
        if confidence < MIN_CONFIDENCE:
            continue

        dedup_key = (alert.get("alertRef"), alert.get("url"), alert.get("param"))
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        risk = alert.get("risk", "0")

        # Translate Docker-internal URL back to user-facing URL
        url = alert.get("url", "")
        if original_target:
            url = _translate_url_from_zap(url, original_target)

        # Parse endpoint from URL
        endpoint = url.split("//", 1)[-1].split("/", 1)[-1] if "//" in url else url

        finding = Finding(
            source=FindingSource.DAST,
            severity=SEVERITY_MAP.get(str(risk), Severity.INFO),
            title=alert.get("name", "Unknown ZAP Alert"),
            description=alert.get("description", ""),
            cwe_id=f"CWE-{alert['cweid']}" if alert.get("cweid") and alert["cweid"] != "-1" else None,
            endpoint=f"/{endpoint}" if not endpoint.startswith("/") else endpoint,
            http_method=alert.get("method", "GET"),
            parameter=alert.get("param") or None,
            tool="zap",
            rule_id=alert.get("alertRef"),
            raw_output={
                "url": url,
                "evidence": alert.get("evidence", ""),
                "solution": alert.get("solution", ""),
                "reference": alert.get("reference", ""),
                "attack": alert.get("attack", ""),
                "other": alert.get("other", ""),
            },
        )
        findings.append(finding)

    logger.info(f"ZAP produced {len(findings)} findings")
    return findings