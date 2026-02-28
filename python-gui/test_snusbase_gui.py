"""Tests for the SnusbaseClient API client logic."""

import csv
import json
import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock

import requests

from snusbase_client import (
    SnusbaseClient, parse_csv, SNUSBASE_API_URL,
    flatten_results, export_json, export_csv, export_txt,
)


class TestSnusbaseClient(unittest.TestCase):
    """Test the SnusbaseClient class."""

    def setUp(self):
        self.client = SnusbaseClient(api_key="sb_test_key_12345678901234567")

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
                "Auth": "sb_test_key_12345678901234567",
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
                "Auth": "sb_test_key_12345678901234567",
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

    @patch("snusbase_client.requests.request")
    def test_handles_invalid_json_response(self, mock_request):
        """Test that non-JSON responses are handled gracefully."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.json.side_effect = requests.exceptions.JSONDecodeError(
            "msg", "doc", 0
        )
        mock_response.text = "Internal Server Error"
        mock_request.return_value = mock_response

        status, data = self.client.get_stats()

        self.assertEqual(status, 500)
        self.assertIn("error", data)
        self.assertIn("Invalid JSON response", data["error"])


class TestParseCSV(unittest.TestCase):
    """Test the parse_csv helper function."""

    def test_parse_csv_with_spaces(self):
        self.assertEqual(parse_csv("a, b, c"), ["a", "b", "c"])

    def test_parse_csv_empty_string(self):
        self.assertEqual(parse_csv(""), [])

    def test_parse_csv_whitespace_only_entries(self):
        self.assertEqual(parse_csv("  ,  ,  "), [])

    def test_parse_csv_single_value(self):
        self.assertEqual(parse_csv("hello"), ["hello"])

    def test_parse_csv_strips_whitespace(self):
        self.assertEqual(parse_csv("  foo  ,  bar  "), ["foo", "bar"])


class TestFlattenResults(unittest.TestCase):
    """Test the flatten_results helper function."""

    def test_flatten_grouped_list_results(self):
        data = {
            "results": {
                "DB_A": [{"email": "a@b.com"}, {"email": "c@d.com"}],
                "DB_B": [{"email": "e@f.com"}],
            }
        }
        rows = flatten_results(data)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["_source"], "DB_A")
        self.assertEqual(rows[0]["email"], "a@b.com")
        self.assertEqual(rows[2]["_source"], "DB_B")

    def test_flatten_dict_results(self):
        data = {
            "results": {
                "1.2.3.4": {"country": "US", "city": "NYC"},
            }
        }
        rows = flatten_results(data)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["_source"], "1.2.3.4")
        self.assertEqual(rows[0]["country"], "US")

    def test_flatten_empty_results(self):
        self.assertEqual(flatten_results({"results": {}}), [])
        self.assertEqual(flatten_results({}), [])

    def test_flatten_no_results_key(self):
        data = {"DB_A": [{"email": "a@b.com"}]}
        rows = flatten_results(data)
        self.assertEqual(len(rows), 1)


class TestExportFunctions(unittest.TestCase):
    """Test the export_json, export_csv, and export_txt functions."""

    def setUp(self):
        self.sample_data = {
            "results": {
                "DB_A": [
                    {"email": "a@b.com", "password": "pw1"},
                    {"email": "c@d.com", "password": "pw2"},
                ],
            }
        }
        self.tmpdir = tempfile.mkdtemp()

    def test_export_json(self):
        path = os.path.join(self.tmpdir, "out.json")
        export_json(self.sample_data, path)
        with open(path, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        self.assertEqual(loaded, self.sample_data)

    def test_export_csv(self):
        path = os.path.join(self.tmpdir, "out.csv")
        export_csv(self.sample_data, path)
        with open(path, "r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["email"], "a@b.com")
        self.assertEqual(rows[0]["_source"], "DB_A")
        self.assertEqual(rows[1]["password"], "pw2")

    def test_export_csv_empty(self):
        path = os.path.join(self.tmpdir, "empty.csv")
        export_csv({"results": {}}, path)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertEqual(content, "")

    def test_export_txt(self):
        path = os.path.join(self.tmpdir, "out.txt")
        export_txt(self.sample_data, path)
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 2)
        self.assertIn("_source=DB_A", lines[0])
        self.assertIn("email=a@b.com", lines[0])

    def test_export_txt_empty(self):
        path = os.path.join(self.tmpdir, "empty.txt")
        export_txt({"results": {}}, path)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertEqual(content, "")

    def test_export_json_whois_data(self):
        """Test exporting IP WHOIS-style dict results."""
        data = {"results": {"1.2.3.4": {"country": "US"}}}
        path = os.path.join(self.tmpdir, "whois.json")
        export_json(data, path)
        with open(path, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        self.assertEqual(loaded["results"]["1.2.3.4"]["country"], "US")

    def test_export_csv_whois_data(self):
        """Test CSV export with dict-style (non-list) results."""
        data = {"results": {"1.2.3.4": {"country": "US", "city": "NYC"}}}
        path = os.path.join(self.tmpdir, "whois.csv")
        export_csv(data, path)
        with open(path, "r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["_source"], "1.2.3.4")
        self.assertEqual(rows[0]["country"], "US")


if __name__ == "__main__":
    unittest.main()
