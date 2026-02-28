"""Snusbase API client module."""

import csv
import json
import os

import requests


SNUSBASE_API_URL = "https://api.snusbase.com/"


class SnusbaseClient:
    """Client for interacting with the Snusbase API."""

    def __init__(self, api_key=""):
        self.api_key = api_key

    def _send_request(self, endpoint, body=None):
        """Send a request to the Snusbase API."""
        headers = {
            "Auth": self.api_key,
            "Content-Type": "application/json",
        }
        method = "POST" if body else "GET"
        url = SNUSBASE_API_URL + endpoint
        try:
            response = requests.request(
                method, url, headers=headers, json=body, timeout=30
            )
        except requests.exceptions.ConnectionError as exc:
            return 0, {"error": f"Connection failed: {exc}"}
        except requests.exceptions.Timeout as exc:
            return 0, {"error": f"Request timed out: {exc}"}
        except requests.exceptions.RequestException as exc:
            return 0, {"error": f"Request failed: {exc}"}
        try:
            data = response.json()
        except requests.exceptions.JSONDecodeError:
            data = {"error": "Invalid JSON response", "body": response.text[:500]}
        return response.status_code, data

    def get_stats(self):
        """Retrieve database statistics (no authentication required)."""
        return self._send_request("data/stats")

    def search(self, terms, types, wildcard=False, group_by=None, tables=None):
        """Search the Snusbase database."""
        body = {"terms": terms, "types": types}
        if wildcard:
            body["wildcard"] = True
        if group_by is not None:
            body["group_by"] = group_by
        if tables:
            body["tables"] = tables
        return self._send_request("data/search", body)

    def combo_lookup(self, terms, types, wildcard=False, group_by=None):
        """Search the combolist database."""
        body = {"terms": terms, "types": types}
        if wildcard:
            body["wildcard"] = True
        if group_by is not None:
            body["group_by"] = group_by
        return self._send_request("tools/combo-lookup", body)

    def hash_lookup(self, terms, types, wildcard=False, group_by=None):
        """Search the hash database."""
        body = {"terms": terms, "types": types}
        if wildcard:
            body["wildcard"] = True
        if group_by is not None:
            body["group_by"] = group_by
        return self._send_request("tools/hash-lookup", body)

    def ip_whois(self, terms):
        """Retrieve WHOIS information for IP addresses."""
        body = {"terms": terms}
        return self._send_request("tools/ip-whois", body)


def parse_csv(text):
    """Parse comma-separated values into a list of stripped strings."""
    return [t.strip() for t in text.split(",") if t.strip()]


def flatten_results(data):
    """Flatten nested API results into a list of flat dictionaries.

    Handles the grouped result structure returned by the Snusbase API where
    results are nested under group keys (e.g. database names, IPs).
    """
    rows = []
    results = data.get("results", data)
    if not isinstance(results, dict):
        return rows
    for group_key, entries in results.items():
        if isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, dict):
                    row = {"_source": group_key}
                    row.update(entry)
                    rows.append(row)
        elif isinstance(entries, dict):
            row = {"_source": group_key}
            row.update(entries)
            rows.append(row)
    return rows


def export_json(data, filepath):
    """Export API response data to a JSON file."""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def export_csv(data, filepath):
    """Export API response data to a CSV file.

    Flattens the nested results and writes each record as a CSV row.
    """
    rows = flatten_results(data)
    if not rows:
        with open(filepath, "w", encoding="utf-8", newline="") as f:
            f.write("")
        return
    # Deduplicate field names while preserving insertion order
    fieldnames = list(dict.fromkeys(k for row in rows for k in row.keys()))
    with open(filepath, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def export_txt(data, filepath):
    """Export API response data to a plain text file.

    Writes one record per line with key=value pairs.
    """
    rows = flatten_results(data)
    with open(filepath, "w", encoding="utf-8") as f:
        for row in rows:
            parts = [f"{k}={v}" for k, v in row.items()]
            f.write(" | ".join(parts) + "\n")

