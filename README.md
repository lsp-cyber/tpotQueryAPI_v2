# T-Pot Elasticsearch Query API

A small, robust Python wrapper and CLI for querying **T-Pot** honeypot data directly from **Elasticsearch**. 
It focuses on simple “last _N_ minutes” pulls with resilient error handling and memory‑aware batching, plus a few quick summaries useful for CTI and SOC workflows.

---

## What this repo contains

- **`libQueryTpot.py`** — The library. Handles authenticated ES connections, resilient queries with retries, and helpers to summarize results.
- **`main.py`** — A CLI entry that loads your config, runs a **minutes‑back** query, and prints basic summaries.
- **`README.md`** — You’re here.

> Current query window uses **minutes**, not days. Configure it with `minutes_back` in `config.yml` (see below).

---

## Features

- Query documents from an ES index for the **last N minutes** (`minutes_back`)
- Connection retries with exponential backoff and circuit‑breaker awareness
- Iterative, memory‑friendly retrieval (paged / batched)
- Quick-look summaries:
  - counts by `@type` (honeypot event type)
  - credentials observed (usernames/passwords where present)
  - hashes (e.g., malware indicators where present)
  - `input` fields (common commands / payloads)
- Structured logging to console and logfile

---

## Requirements

- **Python** 3.8+
- Network access to your **T‑Pot Elasticsearch** instance
- An Elasticsearch API Key (recommended) or equivalent auth supported by your ES cluster

### Python dependencies

Create a virtualenv and install the basics:

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -U pip
pip install elasticsearch PyYAML urllib3
```

If you prefer a file, use this `requirements.txt`:

```
elasticsearch
PyYAML
urllib3
```

---

## Configuration (`config.yml`)

`main.py` expects a YAML file with at least these keys. **Names below match what the code reads.**

```yaml
elasticsearch:
  honeypot_host: "https://your-tpot-host:9200"    # ES endpoint
  index_name: "logstash-*"                         # index or pattern
  api_key_id: "YOUR_API_KEY_ID"
  api_key: "YOUR_API_KEY"
  verify_certs: false                              # set true if you have valid TLS

  # Query window (in minutes). Example: last 30 minutes
  minutes_back: 30

logging:
  level: "INFO"                                    # DEBUG|INFO|WARNING|ERROR
  file: "tpot_query.log"
```

**Notes**
- If your ES uses self‑signed TLS, set `verify_certs: false` (or add your CA certs).
- The code currently authenticates via **API Key ID + API Key**.

---

## Quick start

1) Put `config.yml` next to `main.py`  
2) Activate your virtualenv and install deps  
3) Run:

```bash
python main.py
```

What happens:
- The script reads `minutes_back` from `config.yml`
- Pulls documents from `index_name` within the last `N` minutes
- Prints how many results were fetched
- Emits simple summaries (type, credentials, hashes, inputs)

---

## Library usage

Import and use the library directly if you want to integrate with other tools.

```python
from libQueryTpot import TPotQuery

config = {
    "elasticsearch": {
        "honeypot_host": "https://your-tpot-host:9200",
        "index_name": "logstash-*",
        "api_key_id": "YOUR_API_KEY_ID",
        "api_key": "YOUR_API_KEY",
        "verify_certs": False,
        "minutes_back": 15
    }
}

tq = TPotQuery(
    es_host=config["elasticsearch"]["honeypot_host"],
    index_name=config["elasticsearch"]["index_name"],
    api_key_id=config["elasticsearch"]["api_key_id"],
    api_key=config["elasticsearch"]["api_key"],
    config=config
)

# Fetch last N minutes
results = tq.pull_recent_logs(minutes_back=config["elasticsearch"]["minutes_back"])
print(f"Got {len(results)} docs")

# Optional quick summaries
tq.summarize_type_field(entries=results)
tq.summarize_credentials(entries=results)
tq.summarize_hashes(entries=results)
tq.summarize_inputs(entries=results)
```

---

## Logging

`main.py` configures Python’s `logging` using the `logging.level` and `logging.file` values in `config.yml`.  
You’ll see runtime progress and a final “Script executed in … seconds” message on completion.

---

## Troubleshooting

- **Auth failures / 401** — Verify `api_key_id` and `api_key`. Confirm API Key has index read privileges.
- **SSL errors** — If using self‑signed certs, set `verify_certs: false`; better: add your CA to trust store.
- **No results** — Check `index_name` pattern and timestamps; reduce `minutes_back` or verify time sync on T‑Pot host.
- **CircuitBreakerError** — The library will back off and continue; consider lowering batch sizes or query window.

---

## Security considerations

- Avoid logging or exporting sensitive environment details.  
- Treat API keys as secrets. Prefer environment variables or a secret store if you deploy beyond a lab.
- If you later export results to share (e.g., OTX), ensure you **do not** include internal honeypot IPs/hostnames.

---

## License

MIT (or your preferred license).

---

## Roadmap ideas

- Optional day/hour windows in addition to minutes (coexist with `minutes_back`)
- Structured JSON output and CSV export
- Built‑in OTX Pulse helper
- Async client option for very high‑volume pulls
