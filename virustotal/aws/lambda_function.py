# VirusTotal IOC triage - AWS Lambda version.
# Looks up a single URL, domain, or IP against VirusTotal's existing report and
# returns a structured verdict. Lookup-only: it never submits to VirusTotal, so
# indicators from investigations are not made public.
#
# Uses only the Python standard library plus boto3 (included in the Lambda runtime).
# The VirusTotal API key is read from AWS Secrets Manager, never from code.

import base64
import ipaddress
import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import quote, urlparse

import boto3

VT_BASE = "https://www.virustotal.com/api/v3"
SECRET_ID = os.environ.get("SECRET_ID", "vt-triage/api-key")
REQUEST_TIMEOUT = 10
MALICIOUS_THRESHOLD = 2
NEW_DOMAIN_DAYS = 30
MAX_INDICATOR_LENGTH = 2048

secrets_client = boto3.client("secretsmanager")
_api_key = None  # Cached across warm invocations to avoid a Secrets Manager call each time.


def get_api_key():
    global _api_key
    if _api_key is None:
        secret = secrets_client.get_secret_value(SecretId=SECRET_ID)
        _api_key = json.loads(secret["SecretString"])["VT_API_KEY"]
    return _api_key


# ---------------------------------------------------------------------------
# VirusTotal lookup
# ---------------------------------------------------------------------------

class VTError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def vt_get(path):
    """GET a VirusTotal endpoint. Returns parsed JSON, or None if VT has no record."""
    req = urllib.request.Request(
        f"{VT_BASE}{path}",
        headers={"accept": "application/json", "x-apikey": get_api_key()},
    )
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        if e.code == 429:
            raise VTError(429, "VirusTotal rate limit reached; try again in a minute.")
        raise VTError(502, f"VirusTotal returned HTTP {e.code}.")
    except urllib.error.URLError as e:
        raise VTError(504, f"Could not reach VirusTotal: {e.reason}")


def classify(indicator):
    try:
        ipaddress.ip_address(indicator)
        return "ip"
    except ValueError:
        pass
    if "://" in indicator or "/" in indicator:
        return "url"
    return "domain"


def to_iso(timestamp):
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat() if timestamp else None


def lookup(indicator):
    """Return (kind, attributes or None, report_url) for an indicator."""
    kind = classify(indicator)
    if kind == "ip":
        data = vt_get(f"/ip_addresses/{indicator}")
        report_url = f"https://www.virustotal.com/gui/ip-address/{indicator}"
    elif kind == "domain":
        data = vt_get(f"/domains/{quote(indicator, safe='')}")
        report_url = f"https://www.virustotal.com/gui/domain/{indicator}"
    else:
        if not urlparse(indicator).scheme:
            indicator = "http://" + indicator
        vt_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
        data = vt_get(f"/urls/{vt_id}")
        report_url = f"https://www.virustotal.com/gui/url/{vt_id}"

    attributes = data["data"]["attributes"] if data else None
    return kind, indicator, attributes, report_url


def build_result(indicator, kind, attributes, report_url):
    stats = attributes.get("last_analysis_stats", {})
    result = {
        "indicator": indicator,
        "type": kind,
        "found": True,
        "last_analysis_date": to_iso(attributes.get("last_analysis_date")),
        "stats": stats,
        "categories": attributes.get("categories", {}),
        "reputation": attributes.get("reputation"),
        "tags": attributes.get("tags", []),
        "report_url": report_url,
    }
    if kind == "url":
        result["final_url"] = attributes.get("final_url")
        result["title"] = attributes.get("title")
    elif kind == "domain":
        created = attributes.get("creation_date")
        result["creation_date"] = to_iso(created)
        result["domain_age_days"] = (
            (datetime.now(timezone.utc) - datetime.fromtimestamp(created, tz=timezone.utc)).days
            if created else None
        )
        result["registrar"] = attributes.get("registrar")
    elif kind == "ip":
        result["country"] = attributes.get("country")
        result["as_owner"] = attributes.get("as_owner")

    result["flagged"] = is_concerning(result)
    return result


def is_concerning(result):
    stats = result.get("stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    age = result.get("domain_age_days")
    newly_registered = age is not None and age < NEW_DOMAIN_DAYS
    return (
        malicious >= MALICIOUS_THRESHOLD
        or (malicious >= 1 and (suspicious >= 1 or newly_registered))
        or (newly_registered and (result.get("reputation") or 0) < 0)
    )


# ---------------------------------------------------------------------------
# Lambda entry point
# ---------------------------------------------------------------------------

def response(status, body):
    return {
        "statusCode": status,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(body),
    }


def parse_indicator(event):
    """Accept a direct test event ({"indicator": ...}) or an API Gateway request body."""
    if "indicator" in event:
        return event["indicator"]
    body = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode()
    return json.loads(body).get("indicator")


def lambda_handler(event, context):
    try:
        indicator = parse_indicator(event)
    except (ValueError, AttributeError):
        return response(400, {"error": "Request body must be JSON like {\"indicator\": \"example.com\"}."})

    if not isinstance(indicator, str) or not indicator.strip():
        return response(400, {"error": "Missing 'indicator' (a URL, domain, or IP)."})
    indicator = indicator.strip()
    if len(indicator) > MAX_INDICATOR_LENGTH:
        return response(400, {"error": "Indicator is too long."})

    try:
        kind, indicator, attributes, report_url = lookup(indicator)
    except VTError as e:
        print(f"VT error for {indicator!r}: {e}")
        return response(e.status, {"error": str(e)})

    if attributes is None:
        return response(200, {
            "indicator": indicator,
            "type": kind,
            "found": False,
            "flagged": False,
            "message": "VirusTotal has no record of this indicator. Not submitted (lookup-only).",
        })

    result = build_result(indicator, kind, attributes, report_url)
    print(json.dumps({"indicator": indicator, "type": kind, "flagged": result["flagged"]}))
    return response(200, result)
