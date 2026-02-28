"""Tests for the SnusbaseClient API client logic."""

import json
import unittest
from unittest.mock import patch, MagicMock

from snusbase_client import SnusbaseClient, parse_csv, SNUSBASE_API_URL


class TestSnusbaseClient(unittest.TestCase):
    """Test the SnusbaseClient class."""

    def setUp(self):
        self.client = SnusbaseClient(api_key="sb_test_key_1234567890123456")

    @patch("snusbase_client.requests.request")
    def test_get_stats(self, mock_request):
        """Test GET /data/stats endpoint."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"rows": 100, "tables": {}}
        mock_request.return_value = mock_response

        status, data = self.client.get_stats()

        mock_request.assert_called_once_with(
            "GET",
            SNUSBASE_API_URL + "data/stats",
            headers={
                "Auth": "sb_test_key_1234567890123456",
                "Content-Type": "application/json",
            },
            json=None,
            timeout=30,
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["rows"], 100)

    @patch("snusbase_client.requests.request")
    def test_search_basic(self, mock_request):
        """Test POST /data/search with basic parameters."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"took": 1.0, "size": 1, "results": {}}
        mock_request.return_value = mock_response

        status, data = self.client.search(
            terms=["test@example.com"], types=["email"]
        )

        mock_request.assert_called_once_with(
            "POST",
            SNUSBASE_API_URL + "data/search",
            headers={
                "Auth": "sb_test_key_1234567890123456",
                "Content-Type": "application/json",
            },
            json={"terms": ["test@example.com"], "types": ["email"]},
            timeout=30,
        )
        self.assertEqual(status, 200)

    @patch("snusbase_client.requests.request")
    def test_search_with_options(self, mock_request):
        """Test POST /data/search with wildcard, group_by, and tables."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"took": 1.0, "size": 0, "results": {}}
        mock_request.return_value = mock_response

        self.client.search(
            terms=["user%"],
            types=["username"],
            wildcard=True,
            group_by="_domain",
            tables=["TABLE_A"],
        )

        call_args = mock_request.call_args
        body = call_args.kwargs["json"]
        self.assertEqual(body["terms"], ["user%"])
        self.assertEqual(body["types"], ["username"])
        self.assertTrue(body["wildcard"])
        self.assertEqual(body["group_by"], "_domain")
        self.assertEqual(body["tables"], ["TABLE_A"])

    @patch("snusbase_client.requests.request")
    def test_search_group_by_false(self, mock_request):
        """Test that group_by=False is passed correctly."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"took": 1.0, "size": 0, "results": {}}
        mock_request.return_value = mock_response

        self.client.search(
            terms=["test"], types=["email"], group_by=False
        )

        body = mock_request.call_args.kwargs["json"]
        self.assertFalse(body["group_by"])

    @patch("snusbase_client.requests.request")
    def test_combo_lookup(self, mock_request):
        """Test POST /tools/combo-lookup endpoint."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"took": 1.0, "size": 0, "results": {}}
        mock_request.return_value = mock_response

        status, data = self.client.combo_lookup(
            terms=["user@example.com"], types=["username"]
        )

        call_args = mock_request.call_args
        self.assertIn("tools/combo-lookup", call_args.args[1])
        self.assertEqual(status, 200)

    @patch("snusbase_client.requests.request")
    def test_hash_lookup(self, mock_request):
        """Test POST /tools/hash-lookup endpoint."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "took": 0.1,
            "size": 1,
            "results": {"HASHES": [{"hash": "abc", "password": "pw"}]},
        }
        mock_request.return_value = mock_response

        status, data = self.client.hash_lookup(terms=["abc"], types=["hash"])

        call_args = mock_request.call_args
        self.assertIn("tools/hash-lookup", call_args.args[1])
        self.assertEqual(status, 200)
        self.assertEqual(data["results"]["HASHES"][0]["password"], "pw")

    @patch("snusbase_client.requests.request")
    def test_ip_whois(self, mock_request):
        """Test POST /tools/ip-whois endpoint."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "took": 1.0,
            "size": 1,
            "results": {"1.2.3.4": {"country": "US"}},
        }
        mock_request.return_value = mock_response

        status, data = self.client.ip_whois(terms=["1.2.3.4"])

        call_args = mock_request.call_args
        self.assertIn("tools/ip-whois", call_args.args[1])
        body = call_args.kwargs["json"]
        self.assertEqual(body["terms"], ["1.2.3.4"])
        self.assertEqual(status, 200)

    def test_default_api_key_empty(self):
        """Test that a client without an API key has an empty string."""
        client = SnusbaseClient()
        self.assertEqual(client.api_key, "")


class TestParseCSV(unittest.TestCase):
    """Test the parse_csv helper function."""

    def test_basic(self):
        self.assertEqual(parse_csv("a, b, c"), ["a", "b", "c"])

    def test_empty(self):
        self.assertEqual(parse_csv(""), [])

    def test_whitespace_only(self):
        self.assertEqual(parse_csv("  ,  ,  "), [])

    def test_single_value(self):
        self.assertEqual(parse_csv("hello"), ["hello"])

    def test_strips_whitespace(self):
        self.assertEqual(parse_csv("  foo  ,  bar  "), ["foo", "bar"])


if __name__ == "__main__":
    unittest.main()
