
## Objective
Parse authentication logs and flag IPs with repeated failed logins (potential brute force).

## How it works
- Regex extracts IPs from "Failed password" lines
- Counts attempts per IP
- Flags IPs with ≥3 failures
- Exports a CSV report (`alerts.csv`)

## Run
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt  # optional if you use pandas
python analyzer.py
## Output Example
[Alert CSV Screenshot](assets/alerts-sample.png)
