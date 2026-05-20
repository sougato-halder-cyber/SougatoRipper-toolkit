#!/usr/bin/env python3
"""
crypto_tool.py
Data Protection (Cryptography) Module
Contains: FileEncryptor, PasswordGenerator
"""

import os
import secrets
import hashlib
import base64
from cryptography.fernet import Fernet


class FileEncryptor:
    """Encrypt and decrypt files using Fernet symmetric encryption."""

    def __init__(self):
        self.key_dir = "data/crypto"
        os.makedirs(self.key_dir, exist_ok=True)

    def encrypt_file(self, filepath):
        """
        Encrypt a file using Fernet.
        :param filepath: Path to the file to encrypt
        :return: Tuple (key_bytes, output_path)
        """
        key = Fernet.generate_key()
        fernet = Fernet(key)

        with open(filepath, "rb") as f:
            data = f.read()

        encrypted = fernet.encrypt(data)
        out_path = filepath + ".encrypted"

        with open(out_path, "wb") as f:
            f.write(encrypted)

        # Save key for reference (in real apps, store securely!)
        with open(os.path.join(self.key_dir, "last_key.txt"), "w") as kf:
            kf.write(key.decode())

        return key, out_path

    def decrypt_file(self, filepath, key):
        """
        Decrypt a Fernet-encrypted file.
        :param filepath: Path to .encrypted file
        :param key: Fernet key (bytes)
        :return: Output path of decrypted file
        """
        fernet = Fernet(key)

        with open(filepath, "rb") as f:
            encrypted = f.read()

        decrypted = fernet.decrypt(encrypted)
        out_path = filepath.replace(".encrypted", ".decrypted")
        if out_path == filepath:
            out_path += ".decrypted"

        with open(out_path, "wb") as f:
            f.write(decrypted)

        return out_path


class PasswordGenerator:
    """Generate strong passwords and save salted hashes."""

    def __init__(self):
        self.output_dir = "data/crypto"
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_and_save(self, length=16):
        """
        Generate a secure password and save its salted hash.
        :param length: Password length
        :return: Tuple (password, hash_file_path)
        """
        alphabet = (
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789"
            "!@#$%^&*()-_=+[]{}|;:,.<>?"
        )
        password = "".join(secrets.choice(alphabet) for _ in range(length))

        # Generate salt and hash
        salt = secrets.token_hex(16)
        salted = salt + password
        hash_val = hashlib.sha256(salted.encode()).hexdigest()

        # Save to file
        hash_path = os.path.join(self.output_dir, "password_hashes.txt")
        with open(hash_path, "a", encoding="utf-8") as f:
            f.write(f"Salt: {salt} | Hash: {hash_val} | Length: {length}\n")

        return password, hash_path
