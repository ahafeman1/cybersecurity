# VirusTotal IOC triage tool.
# Looks up URLs, domains, and IP addresses against VirusTotal, caches results,
# and writes JSON/text logs of anything that looks concerning.
#
# Lookup-first by design: the tool reads VirusTotal's existing report and only
# submits a URL for a fresh scan when you pass --submit. Submitting makes the URL
# visible to the VirusTotal community, which can leak victim emails or tokens
# embedded in phishing links.

import argparse
import base64
import ipaddress
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

# Keep paths stable even if the script is run from another working directory.
SCRIPT_DIR = Path(__file__).resolve().parent
CACHE_FILE = SCRIPT_DIR / "vt_cache.json"
LOG_DIR = SCRIPT_DIR / "logs"
DEFAULT_TARGETS_FILE = SCRIPT_DIR / "targets.txt"

VT_BASE = "https://www.virustotal.com/api/v3"
CACHE_DAYS = 3                 # Threat intel goes stale quickly; keep this short.
REQUEST_TIMEOUT = 30           # Seconds before a hung request is abandoned.
MIN_SECONDS_BETWEEN_CALLS = 15 # Free API tier allows 4 requests per minute.
MAX_429_RETRIES = 3
POLL_ATTEMPTS = 6

# Flagging thresholds (see is_concerning).
MALICIOUS_THRESHOLD = 2
NEW_DOMAIN_DAYS = 30


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

def load_api_key():
    """Load the VirusTotal API key from keys.env and exit clearly if it is missing."""
    load_dotenv(SCRIPT_DIR / "keys.env")
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        sys.exit("VT_API_KEY not found. Add VT_API_KEY=<your key> to keys.env next to this script.")
    return api_key


class VTClient:
    """Thin VirusTotal API wrapper that handles rate limiting, timeouts, and 429 retries."""

    def __init__(self, api_key):
        self.session = requests.Session()
        self.session.headers.update({"accept": "application/json", "x-apikey": api_key})
        self._last_call = 0.0

    def _wait_for_rate_limit(self):
        elapsed = time.monotonic() - self._last_call
        if elapsed < MIN_SECONDS_BETWEEN_CALLS:
            time.sleep(MIN_SECONDS_BETWEEN_CALLS - elapsed)
        self._last_call = time.monotonic()

    def request(self, method, path, **kwargs):
        """Send a request. Returns the parsed JSON, or None on 404 (VT has no record)."""
        for attempt in range(MAX_429_RETRIES + 1):
            self._wait_for_rate_limit()
            response = self.session.request(method, f"{VT_BASE}{path}", timeout=REQUEST_TIMEOUT, **kwargs)
            if response.status_code == 404:
                return None
            if response.status_code == 429 and attempt < MAX_429_RETRIES:
                time.sleep(60)  # Quota exceeded; wait out the minute window and retry.
                continue
            response.raise_for_status()
            return response.json()
        response.raise_for_status()


# ---------------------------------------------------------------------------
# Indicator handling
# ---------------------------------------------------------------------------

def classify(indicator):
    """Return 'ip', 'url', or 'domain' for an indicator string."""
    try:
        ipaddress.ip_address(indicator)
        return "ip"
    except ValueError:
        pass
    if "://" in indicator or "/" in indicator:
        return "url"
    return "domain"


def url_id(url):
    """VirusTotal URL identifier: unpadded URL-safe base64 of the URL."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def to_iso(timestamp):
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat() if timestamp else None


def build_result(indicator, kind, attributes, report_url):
    """Normalize VT attributes into one result shape shared by every indicator type."""
    stats = attributes.get("last_analysis_stats", {})
    result = {
        "indicator": indicator,
        "type": kind,
        "last_analysis_date": to_iso(attributes.get("last_analysis_date")),
        "stats": stats,
        "categories": attributes.get("categories", {}),
        "reputation": attributes.get("reputation"),
        "total_votes": attributes.get("total_votes", {}),
        "tags": attributes.get("tags", []),
        "report_url": report_url,
    }

    if kind == "url":
        targeted_brand = attributes.get("targeted_brand") or {}
        result.update({
            "final_url": attributes.get("final_url"),
            "redirection_chain": attributes.get("redirection_chain"),
            "title": attributes.get("title"),
            "targeted_brand": {k: v for k, v in targeted_brand.items() if v},
        })
    elif kind == "domain":
        created = attributes.get("creation_date")
        result.update({
            "creation_date": to_iso(created),
            "domain_age_days": (datetime.now(timezone.utc) - datetime.fromtimestamp(created, tz=timezone.utc)).days
            if created else None,
            "registrar": attributes.get("registrar"),
        })
    elif kind == "ip":
        result.update({
            "country": attributes.get("country"),
            "as_owner": attributes.get("as_owner"),
        })

    return result


def submit_and_wait(client, url):
    """Submit a URL VirusTotal has never seen and wait for the analysis to finish.

    Only used with --submit, because submission makes the URL public to the VT community.
    """
    data = client.request("POST", "/urls", data={"url": url})
    analysis_id = data["data"]["id"]

    for _ in range(POLL_ATTEMPTS):
        analysis = client.request("GET", f"/analyses/{analysis_id}")
        if analysis and analysis["data"]["attributes"]["status"] == "completed":
            return True
    return False


def lookup(client, indicator, allow_submit=False):
    """Look up an indicator's existing VT report. Returns (result, status)."""
    kind = classify(indicator)

    if kind == "ip":
        data = client.request("GET", f"/ip_addresses/{indicator}")
        report_url = f"https://www.virustotal.com/gui/ip-address/{indicator}"
    elif kind == "domain":
        data = client.request("GET", f"/domains/{indicator}")
        report_url = f"https://www.virustotal.com/gui/domain/{indicator}"
    else:
        # VT treats scheme-less URLs as http://, so normalize for a consistent identifier.
        if not urlparse(indicator).scheme:
            indicator = "http://" + indicator
        vt_id = url_id(indicator)
        report_url = f"https://www.virustotal.com/gui/url/{vt_id}"
        data = client.request("GET", f"/urls/{vt_id}")

        if data is None and allow_submit:
            if not submit_and_wait(client, indicator):
                return None, "analysis_pending"
            data = client.request("GET", f"/urls/{vt_id}")

    if data is None:
        return None, "not_found"
    return build_result(indicator, kind, data["data"]["attributes"], report_url), "ok"


def is_concerning(result):
    """Flag results with meaningful evidence, without tripping on a single noisy signal."""
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
# Cache and output
# ---------------------------------------------------------------------------

def load_cache():
    if CACHE_FILE.exists():
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_cache(cache):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)


def is_recent(last_checked_str, days=CACHE_DAYS):
    last_checked = datetime.fromisoformat(last_checked_str)
    return (datetime.now(timezone.utc) - last_checked).days < days


def read_targets(args):
    """Collect indicators from command-line arguments and/or a targets file."""
    targets = list(args.indicators)
    targets_file = Path(args.file) if args.file else (DEFAULT_TARGETS_FILE if not targets else None)
    if targets_file:
        if not targets_file.exists():
            sys.exit(f"No indicators given and {targets_file} does not exist.")
        with open(targets_file, "r", encoding="utf-8") as f:
            targets += [line.strip() for line in f if line.strip() and not line.startswith("#")]
    # De-duplicate while keeping order.
    return list(dict.fromkeys(targets))


def write_logs(run_results):
    LOG_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")

    run_log = LOG_DIR / f"run_{timestamp}.json"
    with open(run_log, "w", encoding="utf-8") as f:
        json.dump(run_results, f, indent=2)

    flagged = [r for r in run_results if r.get("result") and is_concerning(r["result"])]

    flagged_json = LOG_DIR / f"flagged_{timestamp}.json"
    with open(flagged_json, "w", encoding="utf-8") as f:
        json.dump(flagged, f, indent=2)

    flagged_txt = LOG_DIR / f"flagged_{timestamp}.txt"
    with open(flagged_txt, "w", encoding="utf-8") as f:
        if not flagged:
            f.write("No flagged indicators this run.\n")
        for r in flagged:
            result = r["result"]
            stats = result.get("stats", {})
            category = next(iter(result.get("categories", {}).values()), "uncategorized")
            age = f" | domain age {result['domain_age_days']}d" if result.get("domain_age_days") is not None else ""
            f.write(
                f"{result['indicator']} | "
                f"{stats.get('malicious', 0)} malicious / {stats.get('suspicious', 0)} suspicious | "
                f"{category}{age} | {result['report_url']}\n"
            )

    return run_log, flagged_json, flagged_txt, flagged


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(description="Triage URLs, domains, and IPs with VirusTotal.")
    parser.add_argument("indicators", nargs="*", help="Indicators to check (URL, domain, or IP).")
    parser.add_argument("-f", "--file", help="File with one indicator per line (default: targets.txt).")
    parser.add_argument(
        "--submit", action="store_true",
        help="Submit URLs VirusTotal has never seen. WARNING: submitted URLs become visible to the VT community.",
    )
    parser.add_argument("--no-cache", action="store_true", help="Ignore cached results and re-query VirusTotal.")
    return parser.parse_args()


def main():
    args = parse_args()
    targets = read_targets(args)
    if not targets:
        sys.exit("No indicators to check.")

    client = VTClient(load_api_key())
    cache = load_cache()
    run_results = []

    for indicator in targets:
        cached = cache.get(indicator)
        if not args.no_cache and cached and cached.get("result") and is_recent(cached["last_checked"]):
            run_results.append({"indicator": indicator, "source": "cache", **cached})
            continue

        try:
            result, status = lookup(client, indicator, allow_submit=args.submit)
        except requests.RequestException as e:
            # One failure should not end the run or lose earlier results.
            print(f"[error] {indicator}: {e}")
            run_results.append({"indicator": indicator, "source": "error", "error": str(e)})
            continue

        if status != "ok":
            note = " (rerun with --submit to scan it)" if status == "not_found" and classify(indicator) == "url" else ""
            print(f"[{status}] {indicator}{note}")
            run_results.append({"indicator": indicator, "source": status})
            continue

        cache[indicator] = {"last_checked": datetime.now(timezone.utc).isoformat(), "result": result}
        save_cache(cache)  # Save after every lookup so a crash never loses completed work.
        run_results.append({"indicator": indicator, "source": "lookup", **cache[indicator]})

    run_log, flagged_json, flagged_txt, flagged = write_logs(run_results)

    print(f"Checked {len(run_results)} indicators: {len(flagged)} flagged for review.")
    print(f"Full log: {run_log.name}")
    print(f"Flagged: {flagged_json.name} / {flagged_txt.name}")


if __name__ == "__main__":
    main()
