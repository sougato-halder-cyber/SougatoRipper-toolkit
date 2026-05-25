#!/usr/bin/env python3
"""
Automated Security & Monitoring Toolkit
Main Application (app.py)
Author: SougatoRipper
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog, simpledialog
import threading
import os
import datetime

from scanner import SubdomainEnumerator, PortScanner
from sqli_tester import SQLiTester
from crypto_tool import FileEncryptor, PasswordGenerator
from monitor import ActivityMonitor
from reporter import ReportGenerator


class SecurityToolkitApp:
    """Main GUI application integrating all security modules."""

    def __init__(self, root):
        self.root = root
        self.root.title("Automated Security & Monitoring Toolkit")
        self.root.geometry("1250x850")
        self.root.minsize(1000, 700)
        self.root.configure(bg="#1e1e2e")

        # Style configuration
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TNotebook", background="#1e1e2e", tabmargins=[2, 5, 2, 0])
        self.style.configure("TNotebook.Tab", font=("Helvetica", 11, "bold"), padding=[15, 5])
        self.style.map("TNotebook.Tab", background=[("selected", "#89b4fa")], foreground=[("selected", "#1e1e2e")])

        self._build_ui()
        self._init_modules()

    def _build_ui(self):
        """Build the main user interface."""
        # Header
        header = tk.Frame(self.root, bg="#181825", height=60)
        header.pack(fill=tk.X)
        header.pack_propagate(False)

        title = tk.Label(
            header,
            text="🔒 Automated Security & Monitoring Toolkit",
            font=("Helvetica", 18, "bold"),
            bg="#181825",
            fg="#cdd6f4"
        )
        title.pack(pady=10)

        # Notebook (Tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create tabs
        self.tab_recon = tk.Frame(self.notebook, bg="#1e1e2e")
        self.tab_vuln = tk.Frame(self.notebook, bg="#1e1e2e")
        self.tab_crypto = tk.Frame(self.notebook, bg="#1e1e2e")
        self.tab_monitor = tk.Frame(self.notebook, bg="#1e1e2e")
        self.tab_reports = tk.Frame(self.notebook, bg="#1e1e2e")

        self.notebook.add(self.tab_recon, text="Reconnaissance")
        self.notebook.add(self.tab_vuln, text="Vulnerability Testing")
        self.notebook.add(self.tab_crypto, text="Data Protection")
        self.notebook.add(self.tab_monitor, text="System Monitoring")
        self.notebook.add(self.tab_reports, text="Reports")

        self._build_recon_tab()
        self._build_vuln_tab()
        self._build_crypto_tab()
        self._build_monitor_tab()
        self._build_reports_tab()

        # Status bar
        self.status = tk.Label(
            self.root,
            text="Ready",
            bd=1,
            relief=tk.SUNKEN,
            anchor=tk.W,
            bg="#181825",
            fg="#a6adc8",
            font=("Helvetica", 10)
        )
        self.status.pack(side=tk.BOTTOM, fill=tk.X)

    def _init_modules(self):
        """Initialize core logic modules."""
        self.subdomain_enum = SubdomainEnumerator()
        self.port_scanner = PortScanner()
        self.sqli_tester = SQLiTester()
        self.file_crypto = FileEncryptor()
        self.pass_gen = PasswordGenerator()
        self.monitor = ActivityMonitor()
        self.reporter = ReportGenerator()

    # ───────────────────────────────
    # Reconnaissance Tab
    # ───────────────────────────────
    def _build_recon_tab(self):
        """Build the Reconnaissance & Network Scanner tab."""
        frame = tk.Frame(self.tab_recon, bg="#1e1e2e")
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Subdomain Enumerator
        sub_frame = tk.LabelFrame(frame, text="Subdomain Enumerator", bg="#313244", fg="#cdd6f4",
                                   font=("Helvetica", 12, "bold"), padx=10, pady=10)
        sub_frame.pack(fill=tk.X, pady=(0, 15))

        tk.Label(sub_frame, text="Target Domain:", bg="#313244", fg="#cdd6f4", font=("Helvetica", 11)).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.entry_domain = tk.Entry(sub_frame, width=40, font=("Helvetica", 11))
        self.entry_domain.grid(row=0, column=1, padx=5, pady=5)
        self.entry_domain.insert(0, "example.com")

        tk.Label(sub_frame, text="Wordlist:", bg="#313244", fg="#cdd6f4", font=("Helvetica", 11)).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.entry_wordlist = tk.Entry(sub_frame, width=40, font=("Helvetica", 11))
        self.entry_wordlist.grid(row=1, column=1, padx=5, pady=5)
        self.entry_wordlist.insert(0, "data/wordlists/subdomains.txt")
        tk.Button(sub_frame, text="Browse", command=self._browse_wordlist, bg="#89b4fa", fg="#1e1e2e",
                  font=("Helvetica", 10, "bold"), cursor="hand2").grid(row=1, column=2, padx=5)

        tk.Button(sub_frame, text="Start Enumeration", command=self._start_subdomain_enum,
                  bg="#a6e3a1", fg="#1e1e2e", font=("Helvetica", 11, "bold"), cursor="hand2").grid(row=2, column=1, pady=10)

        # Port Scanner
        port_frame = tk.LabelFrame(frame, text="Port Scanner", bg="#313244", fg="#cdd6f4",
                                    font=("Helvetica", 12, "bold"), padx=10, pady=10)
        port_frame.pack(fill=tk.X)

        tk.Label(port_frame, text="Target IP/Host:", bg="#313244", fg="#cdd6f4", font=("Helvetica", 11)).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.entry_target_ip = tk.Entry(port_frame, width=40, font=("Helvetica", 11))
        self.entry_target_ip.grid(row=0, column=1, padx=5, pady=5)
        self.entry_target_ip.insert(0, "127.0.0.1")

        tk.Label(port_frame, text="Ports (comma-separated):", bg="#313244", fg="#cdd6f4", font=("Helvetica", 11)).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.entry_ports = tk.Entry(port_frame, width=40, font=("Helvetica", 11))
        self.entry_ports.grid(row=1, column=1, padx=5, pady=5)
        self.entry_ports.insert(0, "80,443,21,22,3306,8080")

        tk.Button(port_frame, text="Scan Ports", command=self._start_port_scan,
                  bg="#a6e3a1", fg="#1e1e2e", font=("Helvetica", 11, "bold"), cursor="hand2").grid(row=2, column=1, pady=10)

        # Output area + Clear button
        out_frame = tk.Frame(frame, bg="#1e1e2e")
        out_frame.pack(fill=tk.BOTH, expand=True, pady=(15, 0))

        self.txt_recon = scrolledtext.ScrolledText(out_frame, height=12, bg="#181825", fg="#cdd6f4",
                                                      font=("Consolas", 10), insertbackground="#cdd6f4")
        self.txt_recon.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        btn_clear = tk.Button(out_frame, text="Clear\nOutput", command=lambda: self.txt_recon.delete(1.0, tk.END),
                              bg="#f38ba8", fg="#1e1e2e", font=("Helvetica", 9, "bold"), cursor="hand2")
        btn_clear.pack(side=tk.RIGHT, padx=(5, 0), fill=tk.Y)

    def _browse_wordlist(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if path:
            self.entry_wordlist.delete(0, tk.END)
            self.entry_wordlist.insert(0, path)

    def _start_subdomain_enum(self):
        domain = self.entry_domain.get().strip()
        wordlist = self.entry_wordlist.get().strip()
        if not domain or not wordlist:
            messagebox.showwarning("Input Error", "Please provide both domain and wordlist path.")
            return
        # FIX #2: Don't clear previous output, append new
        self.txt_recon.insert(tk.END, f"\n{'='*50}\n[+] Starting subdomain enumeration for: {domain} | {datetime.datetime.now().strftime('%H:%M:%S')}\n")
        self.txt_recon.see(tk.END)
        self.status.config(text="Running subdomain enumeration...")
        threading.Thread(target=self._run_subdomain_enum, args=(domain, wordlist), daemon=True).start()

    def _run_subdomain_enum(self, domain, wordlist):
        try:
            results = self.subdomain_enum.enumerate(domain, wordlist)
            self.root.after(0, self._display_recon_results, results, "subdomain")
        except Exception as e:
            self.root.after(0, lambda: self.txt_recon.insert(tk.END, f"[ERROR] {e}\n"))
            self.root.after(0, lambda: self.status.config(text="Ready"))

    def _start_port_scan(self):
        target = self.entry_target_ip.get().strip()
        ports_str = self.entry_ports.get().strip()
        if not target or not ports_str:
            messagebox.showwarning("Input Error", "Please provide target IP and ports.")
            return
        try:
            ports = [int(p.strip()) for p in ports_str.split(",")]
        except ValueError:
            messagebox.showerror("Input Error", "Ports must be comma-separated integers.")
            return
        # FIX #2: Append, don't clear
        self.txt_recon.insert(tk.END, f"\n{'='*50}\n[+] Starting port scan on: {target} | {datetime.datetime.now().strftime('%H:%M:%S')}\n")
        self.txt_recon.see(tk.END)
        self.status.config(text="Scanning ports...")
        threading.Thread(target=self._run_port_scan, args=(target, ports), daemon=True).start()

    def _run_port_scan(self, target, ports):
        try:
            results = self.port_scanner.scan(target, ports)
            self.root.after(0, self._display_recon_results, results, "port")
        except Exception as e:
            self.root.after(0, lambda: self.txt_recon.insert(tk.END, f"[ERROR] {e}\n"))
            self.root.after(0, lambda: self.status.config(text="Ready"))

    def _display_recon_results(self, results, scan_type):
        if scan_type == "subdomain":
            self.txt_recon.insert(tk.END, f"[+] Found {len(results)} active subdomains:\n")
            for sub in results:
                self.txt_recon.insert(tk.END, f"    → {sub}\n")
        else:
            self.txt_recon.insert(tk.END, f"[+] Port Scan Results:\n")
            for port, status, service in results:
                self.txt_recon.insert(tk.END, f"    → Port {port}: {status} ({service})\n")
        self.txt_recon.insert(tk.END, f"[+] Done.\n")
        self.txt_recon.see(tk.END)
        self.status.config(text="Ready")

    # ───────────────────────────────
    # Vulnerability Testing Tab
    # ───────────────────────────────
    def _build_vuln_tab(self):
        """Build the Vulnerability Testing tab."""
        frame = tk.Frame(self.tab_vuln, bg="#1e1e2e")
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # SQL Injection Tester
        sqli_frame = tk.LabelFrame(frame, text="SQL Injection Tester", bg="#313244", fg="#cdd6f4",
                                    font=("Helvetica", 12, "bold"), padx=10, pady=10)
        sqli_frame.pack(fill=tk.X, pady=(0, 15))

        tk.Label(sqli_frame, text="Target URL:", bg="#313244", fg="#cdd6f4", font=("Helvetica", 11)).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.entry_sqli_url = tk.Entry(sqli_frame, width=60, font=("Helvetica", 11))
        self.entry_sqli_url.grid(row=0, column=1, padx=5, pady=5)
        self.entry_sqli_url.insert(0, "http://testphp.vulnweb.com/artists.php?artist=1")

        tk.Label(sqli_frame, text="Parameter:", bg="#313244", fg="#cdd6f4", font=("Helvetica", 11)).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.entry_sqli_param = tk.Entry(sqli_frame, width=30, font=("Helvetica", 11))
        self.entry_sqli_param.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        self.entry_sqli_param.insert(0, "artist")

        tk.Button(sqli_frame, text="Test SQL Injection", command=self._start_sqli_test,
                  bg="#f38ba8", fg="#1e1e2e", font=("Helvetica", 11, "bold"), cursor="hand2").grid(row=2, column=1, sticky=tk.W, pady=10)

        # Password Strength & Brute Force Simulator
        pass_frame = tk.LabelFrame(frame, text="Password Strength & Brute Force Simulator", bg="#313244", fg="#cdd6f4",
                                    font=("Helvetica", 12, "bold"), padx=10, pady=10)
        pass_frame.pack(fill=tk.X)

        tk.Label(pass_frame, text="Password / Hash:", bg="#313244", fg="#cdd6f4", font=("Helvetica", 11)).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.entry_password = tk.Entry(pass_frame, width=40, font=("Helvetica", 11), show="*")
        self.entry_password.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(pass_frame, text="Wordlist:", bg="#313244", fg="#cdd6f4", font=("Helvetica", 11)).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.entry_pass_wordlist = tk.Entry(pass_frame, width=40, font=("Helvetica", 11))
        self.entry_pass_wordlist.grid(row=1, column=1, padx=5, pady=5)
        self.entry_pass_wordlist.insert(0, "data/wordlists/passwords.txt")
        tk.Button(pass_frame, text="Browse", command=self._browse_pass_wordlist, bg="#89b4fa", fg="#1e1e2e",
                  font=("Helvetica", 10, "bold"), cursor="hand2").grid(row=1, column=2, padx=5)

        btn_frame = tk.Frame(pass_frame, bg="#313244")
        btn_frame.grid(row=2, column=1, sticky=tk.W, pady=10)
        tk.Button(btn_frame, text="Check Strength", command=self._check_password_strength,
                  bg="#fab387", fg="#1e1e2e", font=("Helvetica", 11, "bold"), cursor="hand2").pack(side=tk.LEFT, padx=(0, 10))
        tk.Button(btn_frame, text="Brute Force Hash", command=self._start_brute_force,
                  bg="#f38ba8", fg="#1e1e2e", font=("Helvetica", 11, "bold"), cursor="hand2").pack(side=tk.LEFT)

        # Output + Clear
        out_frame = tk.Frame(frame, bg="#1e1e2e")
        out_frame.pack(fill=tk.BOTH, expand=True, pady=(15, 0))
        self.txt_vuln = scrolledtext.ScrolledText(out_frame, height=15, bg="#181825", fg="#cdd6f4",
                                                     font=("Consolas", 10), insertbackground="#cdd6f4")
        self.txt_vuln.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        btn_clear = tk.Button(out_frame, text="Clear\nOutput", command=lambda: self.txt_vuln.delete(1.0, tk.END),
                              bg="#f38ba8", fg="#1e1e2e", font=("Helvetica", 9, "bold"), cursor="hand2")
        btn_clear.pack(side=tk.RIGHT, padx=(5, 0), fill=tk.Y)

    def _browse_pass_wordlist(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if path:
            self.entry_pass_wordlist.delete(0, tk.END)
            self.entry_pass_wordlist.insert(0, path)

    def _start_sqli_test(self):
        url = self.entry_sqli_url.get().strip()
        param = self.entry_sqli_param.get().strip()
        if not url or not param:
            messagebox.showwarning("Input Error", "Please provide URL and parameter name.")
            return
        self.txt_vuln.insert(tk.END, f"\n{'='*50}\n[+] Testing SQL Injection on: {url} | {datetime.datetime.now().strftime('%H:%M:%S')}\n")
        self.txt_vuln.see(tk.END)
        self.status.config(text="Testing SQL Injection...")
        threading.Thread(target=self._run_sqli_test, args=(url, param), daemon=True).start()

    def _run_sqli_test(self, url, param):
        try:
            results = self.sqli_tester.test(url, param)
            self.root.after(0, self._display_sqli_results, results)
        except Exception as e:
            self.root.after(0, lambda: self.txt_vuln.insert(tk.END, f"[ERROR] {e}\n"))
            self.root.after(0, lambda: self.status.config(text="Ready"))

    def _display_sqli_results(self, results):
        self.txt_vuln.insert(tk.END, f"[+] SQL Injection Test Results:\n")
        for payload, vulnerable, detail in results:
            status = "VULNERABLE" if vulnerable else "SAFE"
            self.txt_vuln.insert(tk.END, f"    → Payload: {payload} | Status: {status}\n")
            if detail:
                self.txt_vuln.insert(tk.END, f"      Detail: {detail}\n")
        self.txt_vuln.insert(tk.END, f"[+] Done.\n")
        self.txt_vuln.see(tk.END)
        self.status.config(text="Ready")

    def _check_password_strength(self):
        password = self.entry_password.get()
        if not password:
            messagebox.showwarning("Input Error", "Please enter a password.")
            return
        strength, hash_val = self.sqli_tester.check_password_strength(password)
        self.txt_vuln.insert(tk.END, f"\n{'='*50}\n[+] Password Strength Analysis | {datetime.datetime.now().strftime('%H:%M:%S')}\n")
        self.txt_vuln.insert(tk.END, f"    → Strength: {strength}\n")
        self.txt_vuln.insert(tk.END, f"    → SHA-256 Hash: {hash_val}\n")
        self.txt_vuln.insert(tk.END, f"[+] Done.\n")
        self.txt_vuln.see(tk.END)

    def _start_brute_force(self):
        target_hash = self.entry_password.get().strip()
        wordlist = self.entry_pass_wordlist.get().strip()
        if not target_hash or not wordlist:
            messagebox.showwarning("Input Error", "Please provide hash and wordlist path.")
            return
        self.txt_vuln.insert(tk.END, f"\n{'='*50}\n[+] Starting brute force on hash... | {datetime.datetime.now().strftime('%H:%M:%S')}\n")
        self.txt_vuln.see(tk.END)
        self.status.config(text="Brute forcing hash...")
        threading.Thread(target=self._run_brute_force, args=(target_hash, wordlist), daemon=True).start()

    def _run_brute_force(self, target_hash, wordlist):
        try:
            result = self.sqli_tester.brute_force_hash(target_hash, wordlist)
            self.root.after(0, self._display_brute_results, result)
        except Exception as e:
            self.root.after(0, lambda: self.txt_vuln.insert(tk.END, f"[ERROR] {e}\n"))
            self.root.after(0, lambda: self.status.config(text="Ready"))

    def _display_brute_results(self, result):
        if result:
            self.txt_vuln.insert(tk.END, f"[+] PASSWORD CRACKED: {result}\n")
        else:
            self.txt_vuln.insert(tk.END, f"[-] Password not found in wordlist.\n")
        self.txt_vuln.insert(tk.END, f"[+] Done.\n")
        self.txt_vuln.see(tk.END)
        self.status.config(text="Ready")

    # ───────────────────────────────
    # Data Protection Tab
    # ───────────────────────────────
    def _build_crypto_tab(self):
        """Build the Data Protection (Cryptography) tab."""
        frame = tk.Frame(self.tab_crypto, bg="#1e1e2e")
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # File Encryptor/Decryptor
        file_frame = tk.LabelFrame(frame, text="File Encryptor / Decryptor (Fernet)", bg="#313244", fg="#cdd6f4",
                                    font=("Helvetica", 12, "bold"), padx=10, pady=10)
        file_frame.pack(fill=tk.X, pady=(0, 15))

        tk.Label(file_frame, text="Select File:", bg="#313244", fg="#cdd6f4", font=("Helvetica", 11)).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.entry_crypto_file = tk.Entry(file_frame, width=50, font=("Helvetica", 11))
        self.entry_crypto_file.grid(row=0, column=1, padx=5, pady=5)
        tk.Button(file_frame, text="Browse", command=self._browse_crypto_file, bg="#89b4fa", fg="#1e1e2e",
                  font=("Helvetica", 10, "bold"), cursor="hand2").grid(row=0, column=2, padx=5)

        btn_frame = tk.Frame(file_frame, bg="#313244")
        btn_frame.grid(row=1, column=1, sticky=tk.W, pady=10)
        tk.Button(btn_frame, text="Encrypt File", command=self._encrypt_file,
                  bg="#f38ba8", fg="#1e1e2e", font=("Helvetica", 11, "bold"), cursor="hand2").pack(side=tk.LEFT, padx=(0, 10))
        tk.Button(btn_frame, text="Decrypt File", command=self._decrypt_file,
                  bg="#a6e3a1", fg="#1e1e2e", font=("Helvetica", 11, "bold"), cursor="hand2").pack(side=tk.LEFT)

        # Secure Password Generator
        gen_frame = tk.LabelFrame(frame, text="Secure Password Generator", bg="#313244", fg="#cdd6f4",
                                   font=("Helvetica", 12, "bold"), padx=10, pady=10)
        gen_frame.pack(fill=tk.X)

        tk.Label(gen_frame, text="Length:", bg="#313244", fg="#cdd6f4", font=("Helvetica", 11)).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.spin_length = tk.Spinbox(gen_frame, from_=8, to=64, width=10, font=("Helvetica", 11))
        self.spin_length.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        self.spin_length.delete(0, tk.END)
        self.spin_length.insert(0, "16")

        tk.Button(gen_frame, text="Generate & Save", command=self._generate_password,
                  bg="#cba6f7", fg="#1e1e2e", font=("Helvetica", 11, "bold"), cursor="hand2").grid(row=1, column=1, sticky=tk.W, pady=10)

        # Output + Clear
        out_frame = tk.Frame(frame, bg="#1e1e2e")
        out_frame.pack(fill=tk.BOTH, expand=True, pady=(15, 0))
        self.txt_crypto = scrolledtext.ScrolledText(out_frame, height=12, bg="#181825", fg="#cdd6f4",
                                                      font=("Consolas", 10), insertbackground="#cdd6f4")
        self.txt_crypto.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        btn_clear = tk.Button(out_frame, text="Clear\nOutput", command=lambda: self.txt_crypto.delete(1.0, tk.END),
                              bg="#f38ba8", fg="#1e1e2e", font=("Helvetica", 9, "bold"), cursor="hand2")
        btn_clear.pack(side=tk.RIGHT, padx=(5, 0), fill=tk.Y)

    def _browse_crypto_file(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            self.entry_crypto_file.delete(0, tk.END)
            self.entry_crypto_file.insert(0, path)

    def _encrypt_file(self):
        filepath = self.entry_crypto_file.get().strip()
        if not filepath or not os.path.exists(filepath):
            messagebox.showwarning("Input Error", "Please select a valid file.")
            return
        try:
            key, out_path = self.file_crypto.encrypt_file(filepath)
            self.txt_crypto.insert(tk.END, f"\n{'='*50}\n[+] File encrypted successfully! | {datetime.datetime.now().strftime('%H:%M:%S')}\n")
            self.txt_crypto.insert(tk.END, f"    → Output: {out_path}\n")
            self.txt_crypto.insert(tk.END, f"    → Key (SAVE THIS): {key.decode()}\n")
            self.txt_crypto.insert(tk.END, f"[+] Key also saved to: data/crypto/last_key.txt\n")
            self.txt_crypto.see(tk.END)
            messagebox.showinfo("Success", f"File encrypted!\nKey saved to: data/crypto/last_key.txt")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _decrypt_file(self):
        filepath = self.entry_crypto_file.get().strip()
        if not filepath or not os.path.exists(filepath):
            messagebox.showwarning("Input Error", "Please select a valid encrypted file.")
            return
        # FIX #1: Use simpledialog.askstring instead of filedialog.askstring
        key = simpledialog.askstring("Decryption Key", "Enter the Fernet key:", show="*")
        if not key:
            return
        try:
            # Clean key (remove whitespace/newlines)
            key = key.strip()
            out_path = self.file_crypto.decrypt_file(filepath, key.encode())
            self.txt_crypto.insert(tk.END, f"\n{'='*50}\n[+] File decrypted successfully! | {datetime.datetime.now().strftime('%H:%M:%S')}\n")
            self.txt_crypto.insert(tk.END, f"    → Output: {out_path}\n")
            self.txt_crypto.insert(tk.END, f"[+] Done.\n")
            self.txt_crypto.see(tk.END)
            messagebox.showinfo("Success", f"File decrypted!\nSaved to: {out_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    def _generate_password(self):
        try:
            length = int(self.spin_length.get())
        except ValueError:
            messagebox.showerror("Input Error", "Length must be an integer.")
            return
        password, hash_path = self.pass_gen.generate_and_save(length)
        self.txt_crypto.insert(tk.END, f"\n{'='*50}\n[+] Password generated and saved! | {datetime.datetime.now().strftime('%H:%M:%S')}\n")
        self.txt_crypto.insert(tk.END, f"    → Password: {password}\n")
        self.txt_crypto.insert(tk.END, f"    → Salted Hash saved to: {hash_path}\n")
        self.txt_crypto.insert(tk.END, f"[+] Done.\n")
        self.txt_crypto.see(tk.END)

    # ───────────────────────────────
    # System Monitoring Tab
    # ───────────────────────────────
    def _build_monitor_tab(self):
        """Build the System Monitoring tab."""
        frame = tk.Frame(self.tab_monitor, bg="#1e1e2e")
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        ctrl_frame = tk.LabelFrame(frame, text="Activity Logger & Screenshot Saver", bg="#313244", fg="#cdd6f4",
                                    font=("Helvetica", 12, "bold"), padx=10, pady=10)
        ctrl_frame.pack(fill=tk.X, pady=(0, 15))

        tk.Label(ctrl_frame, text="Interval (seconds):", bg="#313244", fg="#cdd6f4", font=("Helvetica", 11)).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.entry_interval = tk.Entry(ctrl_frame, width=10, font=("Helvetica", 11))
        self.entry_interval.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        self.entry_interval.insert(0, "10")

        tk.Label(ctrl_frame, text="Duration (seconds, 0=∞):", bg="#313244", fg="#cdd6f4", font=("Helvetica", 11)).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.entry_duration = tk.Entry(ctrl_frame, width=10, font=("Helvetica", 11))
        self.entry_duration.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        self.entry_duration.insert(0, "60")

        btn_frame = tk.Frame(ctrl_frame, bg="#313244")
        btn_frame.grid(row=2, column=1, sticky=tk.W, pady=10)
        self.btn_start_monitor = tk.Button(btn_frame, text="Start Monitoring", command=self._start_monitor,
                                           bg="#a6e3a1", fg="#1e1e2e", font=("Helvetica", 11, "bold"), cursor="hand2")
        self.btn_start_monitor.pack(side=tk.LEFT, padx=(0, 10))
        self.btn_stop_monitor = tk.Button(btn_frame, text="Stop Monitoring", command=self._stop_monitor,
                                          bg="#f38ba8", fg="#1e1e2e", font=("Helvetica", 11, "bold"), cursor="hand2", state=tk.DISABLED)
        self.btn_stop_monitor.pack(side=tk.LEFT, padx=(0, 10))
        # FIX #4: View Logs button
        tk.Button(btn_frame, text="View Logs", command=self._view_logs,
                  bg="#89b4fa", fg="#1e1e2e", font=("Helvetica", 11, "bold"), cursor="hand2").pack(side=tk.LEFT)

        # Output + Clear
        out_frame = tk.Frame(frame, bg="#1e1e2e")
        out_frame.pack(fill=tk.BOTH, expand=True, pady=(15, 0))
        self.txt_monitor = scrolledtext.ScrolledText(out_frame, height=15, bg="#181825", fg="#cdd6f4",
                                                       font=("Consolas", 10), insertbackground="#cdd6f4")
        self.txt_monitor.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        btn_clear = tk.Button(out_frame, text="Clear\nOutput", command=lambda: self.txt_monitor.delete(1.0, tk.END),
                              bg="#f38ba8", fg="#1e1e2e", font=("Helvetica", 9, "bold"), cursor="hand2")
        btn_clear.pack(side=tk.RIGHT, padx=(5, 0), fill=tk.Y)

    def _start_monitor(self):
        try:
            interval = int(self.entry_interval.get())
            duration = int(self.entry_duration.get())
        except ValueError:
            messagebox.showerror("Input Error", "Interval and duration must be integers.")
            return
        if interval < 1:
            messagebox.showerror("Input Error", "Interval must be at least 1 second.")
            return

        self.txt_monitor.insert(tk.END, f"\n{'='*50}\n[+] Starting monitoring... | {datetime.datetime.now().strftime('%H:%M:%S')}\n")
        self.txt_monitor.insert(tk.END, f"    → Interval: {interval}s | Duration: {duration if duration > 0 else 'Infinite'}s\n")
        self.txt_monitor.see(tk.END)
        self.status.config(text="Monitoring active...")
        self.btn_start_monitor.config(state=tk.DISABLED)
        self.btn_stop_monitor.config(state=tk.NORMAL)

        self.monitor_thread = threading.Thread(target=self._run_monitor, args=(interval, duration), daemon=True)
        self.monitor_thread.start()

    def _run_monitor(self, interval, duration):
        try:
            self.monitor.start(interval, duration, self._on_monitor_event)
        except Exception as e:
            self.root.after(0, lambda: self.txt_monitor.insert(tk.END, f"[ERROR] {e}\n"))
        finally:
            self.root.after(0, self._monitor_stopped)

    def _on_monitor_event(self, message):
        self.root.after(0, lambda: self.txt_monitor.insert(tk.END, f"{message}\n"))
        self.root.after(0, lambda: self.txt_monitor.see(tk.END))

    def _stop_monitor(self):
        self.monitor.stop()
        self.txt_monitor.insert(tk.END, "[+] Stopping monitoring...\n")
        self.txt_monitor.see(tk.END)

    def _monitor_stopped(self):
        self.btn_start_monitor.config(state=tk.NORMAL)
        self.btn_stop_monitor.config(state=tk.DISABLED)
        self.status.config(text="Ready")
        self.txt_monitor.insert(tk.END, "[+] Monitoring stopped.\n")
        self.txt_monitor.see(tk.END)

    def _view_logs(self):
        """FIX #4: Open activity log file in output window."""
        log_path = "data/activity_log.txt"
        if os.path.exists(log_path):
            with open(log_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.txt_monitor.insert(tk.END, f"\n{'='*50}\n[+] Activity Log Contents:\n")
            self.txt_monitor.insert(tk.END, content)
            self.txt_monitor.insert(tk.END, f"\n[+] End of log.\n")
            self.txt_monitor.see(tk.END)
        else:
            messagebox.showwarning("No Logs", f"Log file not found: {log_path}\nStart monitoring first.")

    # ───────────────────────────────
    # Reports Tab
    # ───────────────────────────────
    def _build_reports_tab(self):
        """Build the Reports tab."""
        frame = tk.Frame(self.tab_reports, bg="#1e1e2e")
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        ctrl_frame = tk.LabelFrame(frame, text="Automated Report Generation", bg="#313244", fg="#cdd6f4",
                                    font=("Helvetica", 12, "bold"), padx=10, pady=10)
        ctrl_frame.pack(fill=tk.X, pady=(0, 15))

        tk.Label(ctrl_frame, text="Report Title:", bg="#313244", fg="#cdd6f4", font=("Helvetica", 11)).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.entry_report_title = tk.Entry(ctrl_frame, width=50, font=("Helvetica", 11))
        self.entry_report_title.grid(row=0, column=1, padx=5, pady=5)
        self.entry_report_title.insert(0, "Security Assessment Report")

        # FIX #3: Removed scan result file browse option
        tk.Label(ctrl_frame, text="Mode:", bg="#313244", fg="#cdd6f4", font=("Helvetica", 11)).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.report_mode = ttk.Combobox(ctrl_frame, values=["Demo Data", "Auto-Collect from Modules"], width=30, font=("Helvetica", 11))
        self.report_mode.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        self.report_mode.set("Demo Data")
        self.report_mode.config(state="readonly")

        tk.Button(ctrl_frame, text="Generate Excel Report", command=self._generate_report,
                  bg="#cba6f7", fg="#1e1e2e", font=("Helvetica", 11, "bold"), cursor="hand2").grid(row=2, column=1, sticky=tk.W, pady=10)

        # Output + Clear
        out_frame = tk.Frame(frame, bg="#1e1e2e")
        out_frame.pack(fill=tk.BOTH, expand=True, pady=(15, 0))
        self.txt_reports = scrolledtext.ScrolledText(out_frame, height=15, bg="#181825", fg="#cdd6f4",
                                                       font=("Consolas", 10), insertbackground="#cdd6f4")
        self.txt_reports.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        btn_clear = tk.Button(out_frame, text="Clear\nOutput", command=lambda: self.txt_reports.delete(1.0, tk.END),
                              bg="#f38ba8", fg="#1e1e2e", font=("Helvetica", 9, "bold"), cursor="hand2")
        btn_clear.pack(side=tk.RIGHT, padx=(5, 0), fill=tk.Y)

    def _generate_report(self):
        title = self.entry_report_title.get().strip()
        mode = self.report_mode.get()
        if not title:
            messagebox.showwarning("Input Error", "Please provide a report title.")
            return
        self.txt_reports.insert(tk.END, f"\n{'='*50}\n[+] Generating report: {title} | Mode: {mode} | {datetime.datetime.now().strftime('%H:%M:%S')}\n")
        self.txt_reports.see(tk.END)
        self.status.config(text="Generating report...")
        threading.Thread(target=self._run_generate_report, args=(title, mode), daemon=True).start()

    def _run_generate_report(self, title, mode):
        try:
            # FIX #3: No external file needed, auto-generate based on mode
            report_path = self.reporter.generate_excel(title, mode=mode)
            self.root.after(0, lambda: self.txt_reports.insert(tk.END, f"[+] Report saved to: {report_path}\n"))
            self.root.after(0, lambda: self.txt_reports.insert(tk.END, f"[+] Done.\n"))
            self.root.after(0, lambda: messagebox.showinfo("Success", f"Report generated!\n{report_path}"))
        except Exception as e:
            self.root.after(0, lambda: self.txt_reports.insert(tk.END, f"[ERROR] {e}\n"))
        finally:
            self.root.after(0, lambda: self.status.config(text="Ready"))


if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityToolkitApp(root)
    root.mainloop()
