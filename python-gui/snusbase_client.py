"""Snusbase API client module."""

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
        response = requests.request(
            method, url, headers=headers, json=body, timeout=30
        )
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
