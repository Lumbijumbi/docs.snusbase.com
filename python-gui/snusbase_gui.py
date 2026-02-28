"""
Snusbase API GUI - A Python tkinter GUI to interact with the Snusbase API.

Supports all API endpoints:
  - Database Statistics (GET /data/stats)
  - Database Search (POST /data/search)
  - Combo Lookup (POST /tools/combo-lookup)
  - Hash Lookup (POST /tools/hash-lookup)
  - IP WHOIS Lookup (POST /tools/ip-whois)
"""

import html
import json
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

import requests

from snusbase_client import SnusbaseClient, parse_csv


class SnusbaseGUI:
    """Main GUI application for Snusbase API."""

    def __init__(self, root):
        self.root = root
        self.root.title("Snusbase API GUI")
        self.root.geometry("900x700")
        self.root.minsize(700, 500)

        self.client = SnusbaseClient()
        self._build_ui()

    def _build_ui(self):
        """Build the main user interface."""
        # API Key frame at top
        key_frame = ttk.LabelFrame(self.root, text="Authentication", padding=10)
        key_frame.pack(fill=tk.X, padx=10, pady=(10, 5))

        ttk.Label(key_frame, text="API Key:").pack(side=tk.LEFT)
        self.api_key_var = tk.StringVar()
        api_key_entry = ttk.Entry(
            key_frame, textvariable=self.api_key_var, width=50, show="*"
        )
        api_key_entry.pack(side=tk.LEFT, padx=(5, 10), fill=tk.X, expand=True)

        self.show_key_var = tk.BooleanVar(value=False)
        show_key_btn = ttk.Checkbutton(
            key_frame,
            text="Show",
            variable=self.show_key_var,
            command=lambda: api_key_entry.config(
                show="" if self.show_key_var.get() else "*"
            ),
        )
        show_key_btn.pack(side=tk.LEFT)

        # Tabbed notebook for endpoints
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self._build_stats_tab()
        self._build_search_tab()
        self._build_combo_tab()
        self._build_hash_tab()
        self._build_whois_tab()

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(
            self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W
        )
        status_bar.pack(fill=tk.X, padx=10, pady=(0, 10))

    def _create_results_area(self, parent):
        """Create a scrollable text area for displaying results."""
        results_frame = ttk.LabelFrame(parent, text="Results", padding=5)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        text_area = scrolledtext.ScrolledText(
            results_frame, wrap=tk.WORD, font=("Courier", 10), state=tk.DISABLED
        )
        text_area.pack(fill=tk.BOTH, expand=True)
        return text_area

    def _display_result(self, text_area, status_code, data):
        """Display API response in a text area with HTML-escaped output."""
        text_area.config(state=tk.NORMAL)
        text_area.delete("1.0", tk.END)

        escaped = html.escape(json.dumps(data, indent=2, ensure_ascii=False))
        text_area.insert(tk.END, f"Status Code: {status_code}\n\n{escaped}")
        text_area.config(state=tk.DISABLED)

    def _display_error(self, text_area, error_msg):
        """Display an error message in a text area."""
        text_area.config(state=tk.NORMAL)
        text_area.delete("1.0", tk.END)
        text_area.insert(tk.END, f"Error: {html.escape(str(error_msg))}")
        text_area.config(state=tk.DISABLED)

    def _run_in_thread(self, func, text_area):
        """Run an API call in a background thread."""
        self.status_var.set("Sending request...")

        def wrapper():
            try:
                status_code, data = func()
                self.root.after(
                    0, lambda: self._display_result(text_area, status_code, data)
                )
                self.root.after(0, lambda: self.status_var.set("Request complete"))
            except requests.exceptions.RequestException as e:
                self.root.after(0, lambda: self._display_error(text_area, e))
                self.root.after(0, lambda: self.status_var.set("Request failed"))

        thread = threading.Thread(target=wrapper, daemon=True)
        thread.start()

    # ---- Database Statistics Tab ----

    def _build_stats_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="Database Statistics")

        ttk.Label(
            tab, text="Retrieve database statistics (no authentication required)."
        ).pack(anchor=tk.W, pady=(0, 5))

        self.stats_results = self._create_results_area(tab)

        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(btn_frame, text="Get Statistics", command=self._on_get_stats).pack(
            side=tk.LEFT
        )

    def _on_get_stats(self):
        self._update_client_key()
        self._run_in_thread(self.client.get_stats, self.stats_results)

    # ---- Database Search Tab ----

    def _build_search_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="Database Search")

        input_frame = ttk.LabelFrame(tab, text="Search Parameters", padding=10)
        input_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(input_frame, text="Terms (comma-separated):").grid(
            row=0, column=0, sticky=tk.W, pady=2
        )
        self.search_terms_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.search_terms_var, width=60).grid(
            row=0, column=1, sticky=tk.EW, padx=5, pady=2
        )

        ttk.Label(input_frame, text="Types:").grid(
            row=1, column=0, sticky=tk.W, pady=2
        )
        types_frame = ttk.Frame(input_frame)
        types_frame.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)

        self.search_type_vars = {}
        search_types = ["email", "username", "lastip", "password", "hash", "name", "_domain"]
        for i, t in enumerate(search_types):
            var = tk.BooleanVar(value=(t == "email"))
            cb = ttk.Checkbutton(types_frame, text=t, variable=var)
            cb.grid(row=i // 4, column=i % 4, sticky=tk.W, padx=5)
            self.search_type_vars[t] = var

        ttk.Label(input_frame, text="Wildcard:").grid(
            row=2, column=0, sticky=tk.W, pady=2
        )
        self.search_wildcard_var = tk.BooleanVar()
        ttk.Checkbutton(
            input_frame, text="Enable", variable=self.search_wildcard_var
        ).grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)

        ttk.Label(input_frame, text="Group By:").grid(
            row=3, column=0, sticky=tk.W, pady=2
        )
        self.search_groupby_var = tk.StringVar(value="db")
        group_combo = ttk.Combobox(
            input_frame,
            textvariable=self.search_groupby_var,
            values=["db", "email", "username", "_domain", "false"],
            width=20,
        )
        group_combo.grid(row=3, column=1, sticky=tk.W, padx=5, pady=2)

        ttk.Label(input_frame, text="Tables (comma-separated, optional):").grid(
            row=4, column=0, sticky=tk.W, pady=2
        )
        self.search_tables_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.search_tables_var, width=60).grid(
            row=4, column=1, sticky=tk.EW, padx=5, pady=2
        )

        input_frame.columnconfigure(1, weight=1)

        self.search_results = self._create_results_area(tab)

        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(btn_frame, text="Search", command=self._on_search).pack(
            side=tk.LEFT
        )

    def _on_search(self):
        self._update_client_key()
        terms = parse_csv(self.search_terms_var.get())
        types = [t for t, v in self.search_type_vars.items() if v.get()]

        if not terms:
            messagebox.showwarning("Input Required", "Please enter at least one search term.")
            return
        if not types:
            messagebox.showwarning("Input Required", "Please select at least one search type.")
            return

        wildcard = self.search_wildcard_var.get()
        group_by_val = self.search_groupby_var.get()
        group_by = False if group_by_val == "false" else group_by_val if group_by_val != "db" else None
        tables_str = self.search_tables_var.get().strip()
        tables = parse_csv(tables_str) if tables_str else None

        self._run_in_thread(
            lambda: self.client.search(terms, types, wildcard, group_by, tables),
            self.search_results,
        )

    # ---- Combo Lookup Tab ----

    def _build_combo_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="Combo Lookup")

        input_frame = ttk.LabelFrame(tab, text="Combo Lookup Parameters", padding=10)
        input_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(input_frame, text="Terms (comma-separated):").grid(
            row=0, column=0, sticky=tk.W, pady=2
        )
        self.combo_terms_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.combo_terms_var, width=60).grid(
            row=0, column=1, sticky=tk.EW, padx=5, pady=2
        )

        ttk.Label(input_frame, text="Types:").grid(
            row=1, column=0, sticky=tk.W, pady=2
        )
        types_frame = ttk.Frame(input_frame)
        types_frame.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)

        self.combo_type_vars = {}
        for i, t in enumerate(["username", "password"]):
            var = tk.BooleanVar(value=(t == "username"))
            ttk.Checkbutton(types_frame, text=t, variable=var).grid(
                row=0, column=i, sticky=tk.W, padx=5
            )
            self.combo_type_vars[t] = var

        ttk.Label(input_frame, text="Wildcard:").grid(
            row=2, column=0, sticky=tk.W, pady=2
        )
        self.combo_wildcard_var = tk.BooleanVar()
        ttk.Checkbutton(
            input_frame, text="Enable", variable=self.combo_wildcard_var
        ).grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)

        ttk.Label(input_frame, text="Group By:").grid(
            row=3, column=0, sticky=tk.W, pady=2
        )
        self.combo_groupby_var = tk.StringVar(value="db")
        ttk.Combobox(
            input_frame,
            textvariable=self.combo_groupby_var,
            values=["db", "username", "false"],
            width=20,
        ).grid(row=3, column=1, sticky=tk.W, padx=5, pady=2)

        input_frame.columnconfigure(1, weight=1)

        self.combo_results = self._create_results_area(tab)

        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(
            btn_frame, text="Combo Lookup", command=self._on_combo_lookup
        ).pack(side=tk.LEFT)

    def _on_combo_lookup(self):
        self._update_client_key()
        terms = parse_csv(self.combo_terms_var.get())
        types = [t for t, v in self.combo_type_vars.items() if v.get()]

        if not terms:
            messagebox.showwarning("Input Required", "Please enter at least one search term.")
            return
        if not types:
            messagebox.showwarning("Input Required", "Please select at least one type.")
            return

        wildcard = self.combo_wildcard_var.get()
        group_by_val = self.combo_groupby_var.get()
        group_by = False if group_by_val == "false" else group_by_val if group_by_val != "db" else None

        self._run_in_thread(
            lambda: self.client.combo_lookup(terms, types, wildcard, group_by),
            self.combo_results,
        )

    # ---- Hash Lookup Tab ----

    def _build_hash_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="Hash Lookup")

        input_frame = ttk.LabelFrame(tab, text="Hash Lookup Parameters", padding=10)
        input_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(input_frame, text="Terms (comma-separated):").grid(
            row=0, column=0, sticky=tk.W, pady=2
        )
        self.hash_terms_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.hash_terms_var, width=60).grid(
            row=0, column=1, sticky=tk.EW, padx=5, pady=2
        )

        ttk.Label(input_frame, text="Types:").grid(
            row=1, column=0, sticky=tk.W, pady=2
        )
        types_frame = ttk.Frame(input_frame)
        types_frame.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)

        self.hash_type_vars = {}
        for i, t in enumerate(["hash", "password"]):
            var = tk.BooleanVar(value=(t == "hash"))
            ttk.Checkbutton(types_frame, text=t, variable=var).grid(
                row=0, column=i, sticky=tk.W, padx=5
            )
            self.hash_type_vars[t] = var

        ttk.Label(input_frame, text="Wildcard:").grid(
            row=2, column=0, sticky=tk.W, pady=2
        )
        self.hash_wildcard_var = tk.BooleanVar()
        ttk.Checkbutton(
            input_frame, text="Enable", variable=self.hash_wildcard_var
        ).grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)

        ttk.Label(input_frame, text="Group By:").grid(
            row=3, column=0, sticky=tk.W, pady=2
        )
        self.hash_groupby_var = tk.StringVar(value="db")
        ttk.Combobox(
            input_frame,
            textvariable=self.hash_groupby_var,
            values=["db", "hash", "false"],
            width=20,
        ).grid(row=3, column=1, sticky=tk.W, padx=5, pady=2)

        input_frame.columnconfigure(1, weight=1)

        self.hash_results = self._create_results_area(tab)

        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(
            btn_frame, text="Hash Lookup", command=self._on_hash_lookup
        ).pack(side=tk.LEFT)

    def _on_hash_lookup(self):
        self._update_client_key()
        terms = parse_csv(self.hash_terms_var.get())
        types = [t for t, v in self.hash_type_vars.items() if v.get()]

        if not terms:
            messagebox.showwarning("Input Required", "Please enter at least one hash or password.")
            return
        if not types:
            messagebox.showwarning("Input Required", "Please select at least one type.")
            return

        wildcard = self.hash_wildcard_var.get()
        group_by_val = self.hash_groupby_var.get()
        group_by = False if group_by_val == "false" else group_by_val if group_by_val != "db" else None

        self._run_in_thread(
            lambda: self.client.hash_lookup(terms, types, wildcard, group_by),
            self.hash_results,
        )

    # ---- IP WHOIS Lookup Tab ----

    def _build_whois_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="IP WHOIS Lookup")

        input_frame = ttk.LabelFrame(tab, text="IP WHOIS Parameters", padding=10)
        input_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(input_frame, text="IP Addresses (comma-separated):").grid(
            row=0, column=0, sticky=tk.W, pady=2
        )
        self.whois_terms_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.whois_terms_var, width=60).grid(
            row=0, column=1, sticky=tk.EW, padx=5, pady=2
        )

        input_frame.columnconfigure(1, weight=1)

        self.whois_results = self._create_results_area(tab)

        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(
            btn_frame, text="IP WHOIS Lookup", command=self._on_whois_lookup
        ).pack(side=tk.LEFT)

    def _on_whois_lookup(self):
        self._update_client_key()
        terms = parse_csv(self.whois_terms_var.get())

        if not terms:
            messagebox.showwarning("Input Required", "Please enter at least one IP address.")
            return

        self._run_in_thread(
            lambda: self.client.ip_whois(terms),
            self.whois_results,
        )

    # ---- Helpers ----

    def _update_client_key(self):
        """Update the client's API key from the entry field."""
        self.client.api_key = self.api_key_var.get().strip()


def main():
    root = tk.Tk()
    SnusbaseGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
