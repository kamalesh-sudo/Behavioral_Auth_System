import json
import logging
import urllib.error
import urllib.request

from app.config import get_settings


def send_security_alert(event: dict) -> None:
    """Send security alerts to an external webhook if configured."""
    settings = get_settings()
    webhook_url = (settings.alert_webhook_url or "").strip()
    if not webhook_url:
        return

    payload = json.dumps(event).encode("utf-8")
    request = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            if response.status >= 300:
                logging.warning("Security alert webhook returned status %s", response.status)
    except urllib.error.URLError as exc:
        logging.error("Failed to deliver security alert webhook: %s", exc)
