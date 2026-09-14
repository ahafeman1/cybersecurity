# VirusTotal URL lookup and cache example.
# This script loads a single API key from the local keys.env file, scans a list of
# hardcoded URLs, and writes JSON/text logs for flagged results.

import os
import base64
import json
import time
from pathlib import Path
from datetime import datetime, timezone
from dotenv import load_dotenv
import requests

# Keep the project-relative file path stable even if the user runs the script
# from a different working directory.
script_dir = Path(__file__).resolve().parent

# Load the API key without checking it into the repo.
load_dotenv(script_dir / "keys.env")
api_key = os.getenv("VT_API_KEY")

# Cache and log files live next to the script in the same folder.
CACHE_FILE = script_dir / "vt_cache.json"
LOG_DIR = script_dir / "logs"
CACHE_DAYS = 30

# Hardcoded example URLs that the project is currently targeting for a batch run.
target_urls = [
    "http://tinyurl.com/2p8x9k3z",
    "spolaect.info",
    "example.com",
    "sans.org",
]

# Common request headers for the public VirusTotal JSON API.
headers = {
    "accept": "application/json",
    "x-apikey": api_key,
    "content-type": "application/x-www-form-urlencoded"
}


def load_cache():
    """Read the cached scan results if the sidecar JSON file exists."""
    if CACHE_FILE.exists():
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    return {}


def save_cache(cache):
    """Persist the request cache to disk so future runs can skip fresh scans."""
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)


def is_recent(last_checked_str, days=CACHE_DAYS):
    """Return True when the cached result is fresher than the chosen cache age."""
    last_checked = datetime.fromisoformat(last_checked_str)
    return (datetime.now(timezone.utc) - last_checked).days < days


def is_concerning(result):
    """Flag a cached/fresh scan when there is evidence of maliciousness or a bad reputation."""
    stats = result.get("stats", {})
    reputation = result.get("reputation") or 0
    votes = result.get("total_votes", {})

    return (
        stats.get("malicious", 0) > 0
        or stats.get("suspicious", 0) > 0
        or reputation < 0
        or votes.get("malicious", 0) > 0
    )


def scan_url(target_url):
    """Runs a full VirusTotal scan + lookup for target_url and returns a dict of structured results."""
    # Step 1: submit the URL to VirusTotal. The response includes an analysis id.
    submit_endpoint = "https://www.virustotal.com/api/v3/urls"
    payload = {"url": target_url}

    response = requests.post(submit_endpoint, data=payload, headers=headers)
    response.raise_for_status()
    data = response.json()
    analysis_id = data["data"]["id"]

    # Step 2: poll the analysis endpoint until the scan has been completed.
    analyses_endpoint = "https://www.virustotal.com/api/v3/analyses/" + analysis_id
    analysis = None
    for _ in range(10):
        response = requests.get(analyses_endpoint, headers=headers)
        response.raise_for_status()
        analysis = response.json()
        status = analysis["data"]["attributes"]["status"]
        if status == "completed":
            break
        time.sleep(3)

    # Continue with the completed analysis object. The stats and category data are
    # pulled from the analysis attributes; those are stable for the public schema.
    attributes = analysis["data"]["attributes"]
    stats = attributes.get("stats", {})
    scan_date = attributes.get("date")

    # Step 3: fetch the URL object for richer metadata such as reputation,
    # total votes, title, final_url, and tags when VirusTotal provides them.
    # The object id is derived from the target URL string, then encoded in the same
    # safe way the VirusTotal docs describe for URL objects.
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    url_object_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    response = requests.get(url_object_endpoint, headers=headers)
    response.raise_for_status()
    url_object = response.json()
    url_attributes = url_object["data"]["attributes"]

    # Some relationships are nested dictionaries; clean out empty entries so the final
    # compact view stays readable.
    targeted_brand_raw = url_attributes.get("targeted_brand", {})
    targeted_brand = {v: b for v, b in targeted_brand_raw.items() if b} if targeted_brand_raw else {}

    # Return a single structured result object that the cache and loggers can use.
    result = {
        "url": target_url,
        "scanned_at": datetime.fromtimestamp(scan_date, tz=timezone.utc).isoformat() if scan_date else None,
        "stats": stats,
        "categories": attributes.get("categories", {}),
        "final_url": url_attributes.get("final_url"),
        "redirection_chain": url_attributes.get("redirection_chain"),
        "title": url_attributes.get("title"),
        "targeted_brand": targeted_brand,
        "reputation": url_attributes.get("reputation"),
        "total_votes": url_attributes.get("total_votes", {}),
        "tags": url_attributes.get("tags", []),
        "report_url": f"https://www.virustotal.com/gui/url/{url_id}"
    }

    return result


def main():
    """Main workflow: load cache, scan missing URLs, update JSON/text logs."""
    cache = load_cache()
    run_results = []

    # Iterate through the hardcoded queue. Cache hits skip network calls to avoid
    # unnecessary work; fresh scans are stored so we can reuse them later.
    for target_url in target_urls:
        cached_entry = cache.get(target_url)

        if cached_entry and "result" in cached_entry and is_recent(cached_entry["last_checked"]):
            run_results.append({
                "url": target_url,
                "source": "cache",
                "last_checked": cached_entry["last_checked"],
                "result": cached_entry["result"]
            })
        else:
            result = scan_url(target_url)
            cache[target_url] = {
                "last_checked": datetime.now(timezone.utc).isoformat(),
                "result": result
            }
            run_results.append({
                "url": target_url,
                "source": "fresh_scan",
                "last_checked": cache[target_url]["last_checked"],
                "result": result
            })
            time.sleep(15)  # Only pause after a fresh scan; cached checks do not wait.

    # Save the merged cache object for future reuse.
    save_cache(cache)

    # Create a file-log directory if it is missing.
    LOG_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d_%H%M')

    # --- Full run log (everything checked this run) ---
    log_filename = f"run_{timestamp}.json"
    with open(LOG_DIR / log_filename, "w") as f:
        json.dump(run_results, f, indent=2)

    # --- Flagged-only results ---
    flagged_results = [r for r in run_results if is_concerning(r["result"])]

    flagged_json_filename = f"flagged_{timestamp}.json"
    with open(LOG_DIR / flagged_json_filename, "w") as f:
        json.dump(flagged_results, f, indent=2)

    # --- Flagged quick-read text version ---
    flagged_txt_filename = f"flagged_{timestamp}.txt"
    with open(LOG_DIR / flagged_txt_filename, "w") as f:
        if not flagged_results:
            f.write("No flagged URLs this run.\n")
        for r in flagged_results:
            result = r["result"]
            stats = result.get("stats", {})
            top_category = next(iter(result.get("categories", {}).values()), "uncategorized")
            f.write(
                f"{result['url']} — "
                f"{stats.get('malicious', 0)} malicious / {stats.get('suspicious', 0)} suspicious — "
                f"{top_category} — "
                f"{result['report_url']}\n"
            )

    # Print a short, user-friendly summary of the run.
    print(f"Checked {len(run_results)} URLs — {len(flagged_results)} flagged for review.")
    print(f"Full log: {log_filename}")
    print(f"Flagged: {flagged_json_filename} / {flagged_txt_filename}")


if __name__ == "__main__":
    # Entry point. This simply runs the single Python file flow.
    main()