"""Main Tkinter dashboard for SougatoCracker."""
from __future__ import annotations

import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import os
import sys

from core.crypto_tool import CryptoTool
from core.monitor import ActivityMonitor, ReportGenerator
from core.scanner import ReconScanner
from core.vulnerability import VulnerabilityTester
from core.utils import LOG_FILE


class Dashboard(tk.Tk):
    """Main GUI application class."""

    def __init__(self) -> None:
        super().__init__()
        self.title("SougatoCracker - Automated Security & Monitoring Toolkit")
        self.geometry("1040x720")
        self.minsize(980, 650)

        self.scanner = ReconScanner()
        self.vuln = VulnerabilityTester()
        self.crypto = CryptoTool()
        self.monitor = ActivityMonitor()
        self.reporter = ReportGenerator()

        self.subdomain_results = []
        self.port_results = []
        self.sqli_results = []
        self.monitoring = False
        self.auth_var = tk.BooleanVar(value=False)

        self._build_layout()

    def _build_layout(self) -> None:
        header = ttk.Frame(self, padding=12)
        header.pack(fill="x")
        ttk.Label(header, text="SougatoCracker", font=("Segoe UI", 22, "bold")).pack(side="left")
        ttk.Checkbutton(
            header,
            text="I confirm I have permission to test the selected target/files",
            variable=self.auth_var,
        ).pack(side="right")

        notebook = ttk.Notebook(self)
        notebook.pack(expand=True, fill="both", padx=12, pady=8)

        self._build_recon_tab(notebook)
        self._build_vuln_tab(notebook)
        self._build_crypto_tab(notebook)
        self._build_monitor_tab(notebook)
        self._build_report_tab(notebook)

    def _build_recon_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="Recon Scanner")

        ttk.Label(frame, text="Subdomain Enumerator", font=("Segoe UI", 13, "bold")).grid(row=0, column=0, sticky="w")
        self.domain_entry = ttk.Entry(frame, width=45)
        self.domain_entry.grid(row=1, column=0, sticky="we", pady=5)
        self.domain_entry.insert(0, "example.com")
        ttk.Button(frame, text="Run Subdomain Scan", command=self.run_subdomain_scan).grid(row=1, column=1, padx=8)

        ttk.Label(frame, text="Port Scanner", font=("Segoe UI", 13, "bold")).grid(row=2, column=0, sticky="w", pady=(18, 0))
        self.ip_entry = ttk.Entry(frame, width=45)
        self.ip_entry.grid(row=3, column=0, sticky="we", pady=5)
        self.ip_entry.insert(0, "127.0.0.1")
        ttk.Button(frame, text="Run Port Scan", command=self.run_port_scan).grid(row=3, column=1, padx=8)

        ttk.Label(frame, text="Ports (comma/range):").grid(row=4, column=0, sticky="w")
        self.ports_entry = ttk.Entry(frame, width=45)
        self.ports_entry.grid(row=5, column=0, sticky="we", pady=5)
        self.ports_entry.insert(0, "1-100")

        self.recon_output = tk.Text(frame, height=22, wrap="word")
        self.recon_output.grid(row=6, column=0, columnspan=2, sticky="nsew", pady=12)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(6, weight=1)

    def _build_vuln_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="Vulnerability Testing")

        ttk.Label(frame, text="SQL Injection Tester", font=("Segoe UI", 13, "bold")).grid(row=0, column=0, sticky="w")
        self.url_entry = ttk.Entry(frame, width=70)
        self.url_entry.grid(row=1, column=0, sticky="we", pady=5)
        self.url_entry.insert(0, "http://testphp.vulnweb.com/listproducts.php?cat=1")
        ttk.Button(frame, text="Test SQLi", command=self.run_sqli_test).grid(row=1, column=1, padx=8)

        ttk.Label(frame, text="Password Strength & Hash Simulator", font=("Segoe UI", 13, "bold")).grid(row=2, column=0, sticky="w", pady=(18, 0))
        self.password_entry = ttk.Entry(frame, width=45, show="*")
        self.password_entry.grid(row=3, column=0, sticky="we", pady=5)
        ttk.Button(frame, text="Check Strength", command=self.check_password_strength).grid(row=3, column=1, padx=8)

        ttk.Label(frame, text="Target SHA-256 Hash (for brute force simulator only)").grid(row=4, column=0, sticky="w")
        self.hash_entry = ttk.Entry(frame, width=70)
        self.hash_entry.grid(row=5, column=0, sticky="we", pady=5)
        ttk.Button(frame, text="Crack Using Local Wordlist", command=self.crack_hash).grid(row=5, column=1, padx=8)

        self.vuln_output = tk.Text(frame, height=20, wrap="word")
        self.vuln_output.grid(row=6, column=0, columnspan=2, sticky="nsew", pady=12)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(6, weight=1)

    def _build_crypto_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="Data Protection")

        ttk.Label(frame, text="File Encryptor / Decryptor", font=("Segoe UI", 13, "bold")).pack(anchor="w")
        button_row = ttk.Frame(frame)
        button_row.pack(fill="x", pady=8)
        ttk.Button(button_row, text="Encrypt File", command=self.encrypt_file).pack(side="left", padx=(0, 8))
        ttk.Button(button_row, text="Decrypt File", command=self.decrypt_file).pack(side="left")

        ttk.Separator(frame).pack(fill="x", pady=12)
        ttk.Label(frame, text="Secure Password Generator", font=("Segoe UI", 13, "bold")).pack(anchor="w")
        length_row = ttk.Frame(frame)
        length_row.pack(fill="x", pady=8)
        ttk.Label(length_row, text="Length:").pack(side="left")
        self.length_spin = ttk.Spinbox(length_row, from_=8, to=64, width=8)
        self.length_spin.pack(side="left", padx=8)
        self.length_spin.set(16)
        ttk.Button(length_row, text="Generate", command=self.generate_password).pack(side="left")

        self.crypto_output = tk.Text(frame, height=24, wrap="word")
        self.crypto_output.pack(expand=True, fill="both", pady=12)

    def _build_monitor_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="Monitoring")

        ttk.Label(frame, text="Activity Logger & Screenshot Saver", font=("Segoe UI", 13, "bold")).pack(anchor="w")
        ttk.Label(
            frame,
            text="Screenshots start only when you press Start. Use only on your own computer or with clear permission.",
        ).pack(anchor="w", pady=(4, 10))

        controls = ttk.Frame(frame)
        controls.pack(fill="x")
        ttk.Button(controls, text="Start 10-sec Screenshot Monitoring", command=self.start_monitoring).pack(side="left", padx=(0, 8))
        ttk.Button(controls, text="Stop Monitoring", command=self.stop_monitoring).pack(side="left", padx=(0, 8))
        ttk.Button(controls, text="Capture One Screenshot", command=self.capture_once).pack(side="left", padx=(0, 8))
        ttk.Button(controls, text="Show Log File", command=self.show_log_file).pack(side="left", padx=(0, 8))
        ttk.Button(controls, text="Open Log Folder", command=self.open_log_folder).pack(side="left")

        self.monitor_output = tk.Text(frame, height=25, wrap="word")
        self.monitor_output.pack(expand=True, fill="both", pady=12)

    def _build_report_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="Report")
        ttk.Label(frame, text="Automated Report Generation", font=("Segoe UI", 13, "bold")).pack(anchor="w")
        report_controls = ttk.Frame(frame)
        report_controls.pack(fill="x", pady=10)
        ttk.Button(report_controls, text="Generate Excel Report", command=self.generate_report).pack(side="left", padx=(0, 8))
        ttk.Button(report_controls, text="Show Log File", command=self.show_report_log_file).pack(side="left")
        self.report_output = tk.Text(frame, height=26, wrap="word")
        self.report_output.pack(expand=True, fill="both")

    def _require_authorization(self) -> bool:
        if not self.auth_var.get():
            messagebox.showwarning("Authorization required", "Please confirm you have permission before testing.")
            return False
        return True

    def _run_threaded(self, task) -> None:
        threading.Thread(target=task, daemon=True).start()

    def run_subdomain_scan(self) -> None:
        if not self._require_authorization():
            return

        def task():
            try:
                self._append(self.recon_output, "Starting subdomain scan...\n")
                self.subdomain_results = self.scanner.enumerate_subdomains(self.domain_entry.get())
                for result in self.subdomain_results:
                    self._append(self.recon_output, f"{result.target} | {result.status} | {result.details}\n")
                self._append(self.recon_output, f"Done. Active found: {len(self.subdomain_results)}\n\n")
            except Exception as exc:
                self._append(self.recon_output, f"Error: {exc}\n")

        self._run_threaded(task)

    def run_port_scan(self) -> None:
        if not self._require_authorization():
            return

        def task():
            try:
                ports = self.scanner.parse_ports(self.ports_entry.get())
                self._append(self.recon_output, f"Starting port scan for {len(ports)} port(s): {self.ports_entry.get()}...\n")
                self.port_results = self.scanner.scan_ports(self.ip_entry.get(), ports)
                for port, status, service in self.port_results:
                    self._append(self.recon_output, f"Port {port}: {status} ({service})\n")
                self._append(self.recon_output, f"Done. Open ports: {len(self.port_results)}\n\n")
            except Exception as exc:
                self._append(self.recon_output, f"Error: {exc}\n")

        self._run_threaded(task)

    def run_sqli_test(self) -> None:
        if not self._require_authorization():
            return

        def task():
            try:
                self._append(self.vuln_output, "Starting SQLi test...\n")
                self.sqli_results = self.vuln.test_sqli(self.url_entry.get())
                for payload, result, evidence in self.sqli_results:
                    self._append(self.vuln_output, f"Payload: {payload} | {result} | {evidence}\n")
                self._append(self.vuln_output, "SQLi test complete.\n\n")
            except Exception as exc:
                self._append(self.vuln_output, f"Error: {exc}\n")

        self._run_threaded(task)

    def check_password_strength(self) -> None:
        password = self.password_entry.get()
        strength, advice = self.vuln.check_password_strength(password)
        self._append(self.vuln_output, f"Password Strength: {strength}\n{advice}\n\n")

    def hash_password(self) -> None:
        """Kept for code demonstration; GUI strength button does not reveal the hash."""
        password = self.password_entry.get()
        digest = self.vuln.sha256_hash(password)
        self.hash_entry.delete(0, tk.END)
        self.hash_entry.insert(0, digest)
        self._append(self.vuln_output, "Hash created for brute-force simulator only.\n")

    def crack_hash(self) -> None:
        try:
            found, result = self.vuln.crack_hash(self.hash_entry.get())
            self._append(self.vuln_output, f"Crack result: {found} | {result}\n")
        except Exception as exc:
            self._append(self.vuln_output, f"Error: {exc}\n")

    def encrypt_file(self) -> None:
        selected = filedialog.askopenfilename(title="Select file to encrypt")
        if selected:
            try:
                output = self.crypto.encrypt_file(selected)
                self._append(self.crypto_output, f"Encrypted file saved: {output}\n")
            except Exception as exc:
                self._append(self.crypto_output, f"Error: {exc}\n")

    def decrypt_file(self) -> None:
        selected = filedialog.askopenfilename(title="Select encrypted file to decrypt")
        if selected:
            try:
                output = self.crypto.decrypt_file(selected)
                self._append(self.crypto_output, f"Decrypted file saved: {output}\n")
            except Exception as exc:
                self._append(self.crypto_output, f"Error: {exc}\n")

    def generate_password(self) -> None:
        password, salt, salted_hash = self.crypto.generate_password(int(self.length_spin.get()))
        self._append(self.crypto_output, f"Password: {password}\nSalt: {salt}\nSalted SHA-256: {salted_hash}\n\n")

    def start_monitoring(self) -> None:
        self.monitoring = True
        self._append(self.monitor_output, "Monitoring started. Capturing every 10 seconds.\n")
        self._schedule_screenshot()

    def stop_monitoring(self) -> None:
        self.monitoring = False
        self.monitor.write_log("Screenshot monitoring stopped by user.")
        self._append(self.monitor_output, "Monitoring stopped.\n")

    def capture_once(self) -> None:
        try:
            output = self.monitor.capture_screenshot()
            self._append(self.monitor_output, f"Screenshot saved: {output}\n")
        except Exception as exc:
            self._append(self.monitor_output, f"Error: {exc}\n")

    def _schedule_screenshot(self) -> None:
        if not self.monitoring:
            return
        self.capture_once()
        self.after(10000, self._schedule_screenshot)


    def show_log_file(self) -> None:
        if not LOG_FILE.exists():
            self.monitor.write_log("Log file created from Show Log File button.")
        content = LOG_FILE.read_text(encoding="utf-8") if LOG_FILE.exists() else "Log file not found."
        self._append(self.monitor_output, f"Log file: {LOG_FILE}\n{content}\n")

    def show_report_log_file(self) -> None:
        if not LOG_FILE.exists():
            self.monitor.write_log("Log file created from Report tab.")
        content = LOG_FILE.read_text(encoding="utf-8") if LOG_FILE.exists() else "Log file not found."
        self._append(self.report_output, f"Log file: {LOG_FILE}\n{content}\n")

    def open_log_folder(self) -> None:
        folder = LOG_FILE.parent
        folder.mkdir(parents=True, exist_ok=True)
        try:
            if sys.platform.startswith("win"):
                os.startfile(folder)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                os.system(f'open "{folder}"')
            else:
                os.system(f'xdg-open "{folder}"')
            self._append(self.monitor_output, f"Opened log folder: {folder}\n")
        except Exception as exc:
            self._append(self.monitor_output, f"Log folder: {folder}\nOpen failed: {exc}\n")

    def generate_report(self) -> None:
        try:
            if not (self.subdomain_results or self.port_results or self.sqli_results):
                self._append(self.report_output, "No module results found. Run a scan/test first; report will contain empty sections, not demo data.\n")
            output = self.reporter.create_report(self.subdomain_results, self.port_results, self.sqli_results)
            self._append(self.report_output, f"Report generated from current live results: {output}\n")
        except Exception as exc:
            self._append(self.report_output, f"Error: {exc}\n")

    def _append(self, widget: tk.Text, text: str) -> None:
        self.after(0, lambda: (widget.insert(tk.END, text), widget.see(tk.END)))


if __name__ == "__main__":
    app = Dashboard()
    app.mainloop()
