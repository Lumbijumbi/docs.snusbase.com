# Snusbase API GUI

A Python tkinter GUI application to interact with all Snusbase API endpoints.

## Features

- **Database Statistics** — Retrieve current database statistics (no authentication required)
- **Database Search** — Search leaked databases by email, username, password, hash, IP, domain, or name
- **Combo Lookup** — Search username/password combinations from combolist databases
- **Hash Lookup** — Look up hashes or reverse-lookup plaintext passwords
- **IP WHOIS Lookup** — Retrieve geolocation and ISP data for IP addresses

## Requirements

- Python 3.7+
- `requests` library

## Installation

```bash
cd python-gui
pip install -r requirements.txt
```

## Usage

```bash
python snusbase_gui.py
```

1. Enter your Snusbase API key in the **Authentication** field at the top.
2. Select a tab for the desired API endpoint.
3. Fill in the required parameters and click the action button.
4. Results are displayed in the results pane as formatted JSON.

## API Key

Your API key starts with `sb` followed by 28 random characters. You can obtain one from [Snusbase](https://snusbase.com). Keep your API key confidential.

## Output Sanitization

All API responses are HTML-escaped before display to protect against potentially malicious data in breach datasets, as recommended in the [API documentation](https://docs.snusbase.com/#important-information).
