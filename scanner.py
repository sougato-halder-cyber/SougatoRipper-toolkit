#!/usr/bin/env python3
"""
scanner.py
Reconnaissance & Network Scanner Module
Contains: SubdomainEnumerator, PortScanner
"""

import socket
import requests
import threading
from urllib.parse import urlparse


class SubdomainEnumerator:
    """Enumerate active subdomains using a wordlist and HTTP requests."""

    def __init__(self, timeout=3):
        self.timeout = timeout
        self.results = []
        self.lock = threading.Lock()

    def enumerate(self, domain, wordlist_path):
        """
        Check for active subdomains.
        :param domain: Target domain (e.g., example.com)
        :param wordlist_path: Path to subdomain wordlist file
        :return: List of active subdomains
        """
        self.results = []
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                subdomains = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

        threads = []
        for sub in subdomains:
            t = threading.Thread(target=self._check_subdomain, args=(sub, domain), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        return sorted(self.results)

    def _check_subdomain(self, sub, domain):
        """Check if a subdomain resolves and responds to HTTP."""
        url = f"http://{sub}.{domain}"
        try:
            response = requests.get(url, timeout=self.timeout, allow_redirects=True)
            if response.status_code < 400:
                with self.lock:
                    self.results.append(f"{sub}.{domain} (HTTP {response.status_code})")
        except requests.RequestException:
            pass


class PortScanner:
    """Scan target IP for open ports and identify services."""

    COMMON_SERVICES = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
    }

    def __init__(self, timeout=1):
        self.timeout = timeout
        self.results = []
        self.lock = threading.Lock()

    def scan(self, target, ports):
        """
        Scan ports on target host.
        :param target: IP address or hostname
        :param ports: List of port integers
        :return: List of tuples (port, status, service)
        """
        self.results = []
        threads = []
        for port in ports:
            t = threading.Thread(target=self._check_port, args=(target, port), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        return sorted(self.results, key=lambda x: x[0])

    def _check_port(self, target, port):
        """Attempt TCP connection to a port."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((target, port))
                if result == 0:
                    service = self.COMMON_SERVICES.get(port, "Unknown")
                    with self.lock:
                        self.results.append((port, "OPEN", service))
                else:
                    with self.lock:
                        self.results.append((port, "CLOSED", "N/A"))
        except socket.gaierror:
            with self.lock:
                self.results.append((port, "ERROR", "Invalid host"))
        except Exception as e:
            with self.lock:
                self.results.append((port, "ERROR", str(e)))
