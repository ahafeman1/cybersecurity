# Cybersecurity tools

Security automation scripts I build and maintain.

## VirusTotal IOC triage (`virustotal/VTLookup.py`)

A command-line tool that triages URLs, domains, and IP addresses against the VirusTotal v3 API. It flags the indicators that deserve a closer look.

### Features

- **Lookup-first, privacy-aware.** Reads VirusTotal's existing report instead of submitting. Submitting a URL makes it visible to the whole VirusTotal community, and phishing links often carry victim email addresses or tokens. Submission only happens when you explicitly pass `--submit`.
- **Indicator-aware.** Detects URLs, domains, and IPs and queries the matching endpoint. For domains, it reports registration age, one of the strongest phishing signals.
- **Built for the free API tier.** Spaces calls to stay within 4 requests per minute, retries on HTTP 429, and sets a timeout on every request.
- **Resilient.** A failure on one indicator is logged and skipped. The cache is saved after every lookup, so a crash never loses completed work.
- **Low-noise flagging.** Flags 2+ malicious engine detections, or a single detection backed by a second signal (a suspicious verdict or a newly registered domain). A single community vote is not enough.
- **Local cache.** Results are reused for 3 days to save API quota.

### Setup

```bash
cd virustotal
pip install -r requirements.txt
echo VT_API_KEY=<your key> > keys.env
```

`keys.env`, `targets.txt`, the cache, and logs are all gitignored.

### Usage

```bash
# Check indicators directly
python VTLookup.py spolaect.info http://tinyurl.com/2p8x9k3z 8.8.8.8

# Check a list (one per line); defaults to targets.txt
python VTLookup.py -f targets.txt

# Submit URLs VirusTotal has never seen (makes them public; use with care)
python VTLookup.py --submit http://new-suspicious-site.example/login

# Ignore the cache
python VTLookup.py --no-cache example.com
```

### Output

Written to `virustotal/logs/`:

| File | Contents |
|---|---|
| `run_<timestamp>.json` | Every indicator checked, with full results |
| `flagged_<timestamp>.json` | Only flagged indicators |
| `flagged_<timestamp>.txt` | One-line summary per flagged indicator, with a link to the VirusTotal report |

### Roadmap

- Serverless version on AWS (API Gateway, Lambda, Secrets Manager) with an AI-generated verdict from Amazon Bedrock
- Pull top requested domains from Cisco Secure Access for automated triage
- Blocklist pipeline for confirmed-malicious indicators
