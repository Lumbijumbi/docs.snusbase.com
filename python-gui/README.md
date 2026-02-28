# Snusbase API GUI

A Python tkinter GUI application to interact with all Snusbase API endpoints.

## Features

- **Database Statistics** — Retrieve current database statistics (no authentication required)
- **Database Search** — Search leaked databases by email, username, password, hash, IP, domain, or name
- **Combo Lookup** — Search username/password combinations from combolist databases
- **Hash Lookup** — Look up hashes or reverse-lookup plaintext passwords
- **IP WHOIS Lookup** — Retrieve geolocation and ISP data for IP addresses
- **Bulk Search** — Load search terms from a file and batch-query any endpoint
- **Export Results** — Save any query results to JSON, CSV, or TXT files

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

### Exporting Results

After running any query, click **Export Results** to save the data:

- **JSON** (`.json`) — Full structured API response
- **CSV** (`.csv`) — Flattened records with headers, suitable for spreadsheets
- **TXT** (`.txt`) — One record per line with `key=value` pairs

### Bulk Search

The **Bulk Search** tab lets you load a text file with one search term per line and query them all in batch:

1. Click **Browse...** to select a text file containing search terms (one per line).
2. Choose the target **Endpoint** (Database Search, Combo Lookup, Hash Lookup, or IP WHOIS).
3. Enter the **Types** (e.g., `email`, `username`) — not needed for IP WHOIS.
4. Click **Run Bulk Search**. All results are aggregated and displayed.
5. Click **Export Results** to save the combined output.

## API Key

Your API key starts with `sb` followed by 28 random characters. You can obtain one from [Snusbase](https://snusbase.com). Keep your API key confidential.

## Output Sanitization

All API responses are HTML-escaped before display to protect against potentially malicious data in breach datasets, as recommended in the [API documentation](https://docs.snusbase.com/#important-information).
