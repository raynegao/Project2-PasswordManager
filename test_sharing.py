"""Bonus acceptance checks using disposable recipient keys and fake credentials."""

import base64
import copy
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from password_manager import AuthenticationError, Vault, VaultError
from sharing import generate_keypair, open_share, share_entry


class SharingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.keys.cleanup)
        cls.keydir = Path(cls.keys.name)
        cls.passphrase = "Recipient test passphrase only!"
        cls.private = cls.keydir / "recipient-private.pem"
        cls.public = cls.keydir / "recipient-public.pem"
        cls.other_private = cls.keydir / "other-private.pem"
        generate_keypair(cls.private, cls.public, cls.passphrase)
        generate_keypair(
            cls.other_private, cls.keydir / "other-public.pem", cls.passphrase
        )

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.vault = Vault.create(
            self.folder / "vault.json", "Test-only master password!"
        )
        self.vault.add("school.example", "test-alice", "Account-for-sharing-only!")
        self.vault.add("private.example", "test-bob", "Do-not-share-this-account!")
        self.output = self.folder / "credential.share.json"
        share_entry(self.vault, "school.example", self.public, self.output)

    def test_correct_recipient_gets_only_requested_entry(self):
        before = self.vault.path.read_bytes()
        entry = open_share(self.output, self.private, self.passphrase)
        self.assertEqual(
            entry,
            {
                "service": "school.example",
                "username": "test-alice",
                "password": "Account-for-sharing-only!",
            },
        )
        self.assertNotIn("Do-not-share-this-account!", self.output.read_text())
        for secret in entry.values():
            self.assertNotIn(secret, self.output.read_text())
        self.assertEqual(self.vault.path.read_bytes(), before)

    def test_other_private_key_cannot_decrypt(self):
        with self.assertRaises(AuthenticationError):
            open_share(self.output, self.other_private, self.passphrase)

    def test_wrong_private_key_passphrase_cannot_decrypt(self):
        with self.assertRaises(AuthenticationError):
            open_share(self.output, self.private, "Wrong recipient passphrase!")

    def test_private_key_is_encrypted_and_cannot_load_without_passphrase(self):
        private_pem = self.private.read_bytes()
        self.assertIn(b"BEGIN ENCRYPTED PRIVATE KEY", private_pem)
        self.assertNotIn(self.passphrase.encode(), private_pem)
        with self.assertRaises(TypeError):
            serialization.load_pem_private_key(private_pem, password=None)

    def test_long_unicode_credential_uses_hybrid_encryption(self):
        password = "长密码🔐" * 300
        self.vault.add("long.example", "同学", password)
        long_share = self.folder / "long.share.json"
        share_entry(self.vault, "long.example", self.public, long_share)
        self.assertEqual(
            open_share(long_share, self.private, self.passphrase)["password"], password
        )

    def test_binary_fields_and_algorithm_metadata_cannot_be_modified(self):
        baseline = json.loads(self.output.read_text())
        for field in (
            "wrapped_key",
            "nonce",
            "ciphertext",
            "key_wrap",
            "cipher",
            "version",
        ):
            with self.subTest(field=field):
                envelope = copy.deepcopy(baseline)
                if field in ("wrapped_key", "nonce", "ciphertext"):
                    raw = bytearray(base64.b64decode(envelope[field]))
                    raw[-1] ^= 1
                    envelope[field] = base64.b64encode(raw).decode()
                elif field == "version":
                    envelope[field] = 2
                else:
                    envelope[field] = "invalid"
                self.output.write_text(json.dumps(envelope))
                with self.assertRaises(AuthenticationError):
                    open_share(self.output, self.private, self.passphrase)

    def test_malformed_shared_files_fail_cleanly(self):
        baseline = json.loads(self.output.read_text())
        cases = ["[]", "null", "{broken", '{"version":1,"version":1}']
        for field, value in (
            ("wrapped_key", "eA=="),
            ("nonce", None),
            ("ciphertext", "%%%"),
            ("version", True),
        ):
            envelope = copy.deepcopy(baseline)
            envelope[field] = value
            cases.append(json.dumps(envelope))
        for field in baseline:
            envelope = copy.deepcopy(baseline)
            del envelope[field]
            cases.append(json.dumps(envelope))
        for i, content in enumerate(cases):
            with self.subTest(case=i):
                self.output.write_text(content)
                with self.assertRaises(VaultError):
                    open_share(self.output, self.private, self.passphrase)

    def test_invalid_or_non_rsa_public_key_is_rejected(self):
        invalid = self.folder / "invalid.pem"
        invalid.write_bytes(b"not a PEM key")
        elliptic = self.folder / "elliptic.pem"
        elliptic.write_bytes(
            ec.generate_private_key(ec.SECP256R1())
            .public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        for path in (invalid, elliptic):
            with self.subTest(path=path.name):
                with self.assertRaises(VaultError):
                    share_entry(
                        self.vault,
                        "school.example",
                        path,
                        self.folder / "unused.share.json",
                    )
        self.assertFalse((self.folder / "unused.share.json").exists())

    def test_invalid_private_key_is_rejected(self):
        invalid = self.folder / "invalid-private.pem"
        invalid.write_bytes(b"not a PEM key")
        with self.assertRaises(AuthenticationError):
            open_share(self.output, invalid, self.passphrase)

    def test_missing_service_and_existing_output_are_not_overwritten(self):
        before = self.output.read_bytes()
        with self.assertRaises(VaultError):
            share_entry(self.vault, "missing.example", self.public, self.output)
        with self.assertRaises(FileExistsError):
            share_entry(self.vault, "school.example", self.public, self.output)
        self.assertEqual(self.output.read_bytes(), before)

    def test_key_generation_refuses_existing_files_and_same_paths(self):
        before = self.private.read_bytes()
        with self.assertRaises(VaultError):
            generate_keypair(
                self.private, self.folder / "new-public.pem", self.passphrase
            )
        self.assertEqual(self.private.read_bytes(), before)
        self.assertFalse((self.folder / "new-public.pem").exists())
        with self.assertRaises(VaultError):
            generate_keypair(
                self.folder / "same.pem", self.folder / "same.pem", self.passphrase
            )

    def test_short_key_passphrase_and_partial_generation_do_not_leave_keys(self):
        private = self.folder / "new-private.pem"
        with self.assertRaises(ValueError):
            generate_keypair(private, self.folder / "public.pem", "short")
        with self.assertRaises(OSError):
            generate_keypair(
                private, self.folder / "missing-dir" / "public.pem", self.passphrase
            )
        self.assertFalse(private.exists())

    @unittest.skipIf(os.name == "nt", "Unix permissions do not apply on Windows")
    def test_private_key_and_share_permissions(self):
        for path in (self.private, self.output):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
