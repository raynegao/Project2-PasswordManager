"""Regression checks for the teacher's explicit acceptance conditions."""

import base64
import copy
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from password_manager import (
    AAD,
    KDF_PARAMS,
    PASSWORD_HASHER,
    AuthenticationError,
    Vault,
    VaultError,
    derive_key,
    generate_password,
)
from storage import MAX_FILE_BYTES, atomic_write, canonical_json


class VaultRegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "vault.json"
        self.master = "Review-only strong master password!"
        self.vault = Vault.create(self.path, self.master)

    def envelope(self):
        return json.loads(self.path.read_text())

    def write(self, envelope):
        self.path.write_text(json.dumps(envelope))

    def test_stored_argon2id_verifier_is_independent_of_encryption_key(self):
        envelope = self.envelope()
        verifier = envelope["master_hash"]
        self.assertTrue(verifier.startswith("$argon2id$"))
        self.assertTrue(PasswordHasher().verify(verifier, self.master))
        hash_salt = verifier.split("$")[-2]
        hash_salt = base64.b64decode(hash_salt + "=" * (-len(hash_salt) % 4))
        kdf_salt = base64.b64decode(envelope["salt"])
        self.assertNotEqual(hash_salt, kdf_salt)
        key = derive_key(self.master, kdf_salt)
        self.assertNotIn(base64.b64encode(key).decode(), self.path.read_text())
        self.assertEqual([p.name for p in self.path.parent.iterdir()], ["vault.json"])

    def test_wrong_short_and_long_passwords_do_not_unlock(self):
        for password in ("", "short", "wrong password long enough"):
            with self.subTest(password_length=len(password)):
                with self.assertRaises(AuthenticationError):
                    Vault.open(self.path, password)

    def test_each_binary_crypto_field_rejects_a_single_bit_change(self):
        original = self.envelope()
        for field in ("salt", "nonce", "ciphertext"):
            with self.subTest(field=field):
                envelope = copy.deepcopy(original)
                raw = bytearray(base64.b64decode(envelope[field]))
                raw[-1] ^= 1
                envelope[field] = base64.b64encode(raw).decode()
                self.write(envelope)
                with self.assertRaises(AuthenticationError):
                    Vault.open(self.path, self.master)

    def test_algorithm_labels_and_kdf_parameters_are_validated(self):
        original = self.envelope()
        changes = [
            ("kdf", "Brgon2id"),
            ("cipher", "BES-256-GCM"),
            ("kdf_params", {**KDF_PARAMS, "memory_cost": 2**30}),
            ("version", True),
            ("version", 999),
        ]
        for field, value in changes:
            with self.subTest(field=field):
                envelope = copy.deepcopy(original)
                envelope[field] = value
                self.write(envelope)
                with self.assertRaises(VaultError):
                    Vault.open(self.path, self.master)

    def test_even_a_valid_new_verifier_for_same_password_fails_aad(self):
        envelope = self.envelope()
        envelope["master_hash"] = PASSWORD_HASHER.hash(self.master)
        self.write(envelope)
        with self.assertRaises(AuthenticationError):
            Vault.open(self.path, self.master)

    def test_untrusted_argon2_parameters_are_rejected_before_verify(self):
        envelope = self.envelope()
        envelope["master_hash"] = envelope["master_hash"].replace(
            "m=65536", "m=1073741824"
        )
        self.write(envelope)
        with patch.object(PasswordHasher, "verify") as verify:
            with self.assertRaises(AuthenticationError):
                Vault.open(self.path, self.master)
            verify.assert_not_called()

    def test_malformed_files_fail_as_vault_errors(self):
        original = self.envelope()
        cases = ["[]", "null", "1", "{}", "{broken", b"\xff"]
        for field, value in (
            ("salt", "eA=="),
            ("salt", None),
            ("nonce", ""),
            ("ciphertext", ""),
            ("ciphertext", "%%%"),
            ("master_hash", None),
            ("master_hash", "$argon2id$garbage"),
            ("kdf_params", []),
        ):
            envelope = copy.deepcopy(original)
            envelope[field] = value
            cases.append(json.dumps(envelope))
        for missing in original:
            envelope = copy.deepcopy(original)
            del envelope[missing]
            cases.append(json.dumps(envelope))
        for i, content in enumerate(cases):
            with self.subTest(case=i):
                self.path.write_bytes(
                    content if isinstance(content, bytes) else content.encode()
                )
                with self.assertRaises(VaultError):
                    Vault.open(self.path, self.master)

    def test_unknown_and_duplicate_fields_are_rejected(self):
        envelope = self.envelope()
        envelope["unauthenticated_note"] = "not allowed"
        self.write(envelope)
        with self.assertRaises(AuthenticationError):
            Vault.open(self.path, self.master)
        self.path.write_text('{"version":2,"version":2}')
        with self.assertRaises(AuthenticationError):
            Vault.open(self.path, self.master)

    def test_authenticated_but_malformed_entries_are_rejected(self):
        envelope = self.envelope()
        header = {k: v for k, v in envelope.items() if k != "ciphertext"}
        key = derive_key(self.master, base64.b64decode(header["salt"]))
        for data in (
            [],
            {"entries": []},
            {"entries": {"site": {"username": 42, "password": "p"}}},
        ):
            with self.subTest(data=data):
                header["nonce"] = base64.b64encode(os.urandom(12)).decode()
                ciphertext = AESGCM(key).encrypt(
                    base64.b64decode(header["nonce"]),
                    json.dumps(data).encode(),
                    AAD + canonical_json(header),
                )
                self.write(
                    {**header, "ciphertext": base64.b64encode(ciphertext).decode()}
                )
                with self.assertRaises(AuthenticationError):
                    Vault.open(self.path, self.master)

    def test_json_formatting_changes_do_not_change_authenticated_meaning(self):
        self.path.write_text(json.dumps(self.envelope(), sort_keys=True))
        self.assertEqual(Vault.open(self.path, self.master).entries, {})

    def test_repeated_save_uses_fresh_salt_and_nonce(self):
        before = self.envelope()
        self.vault.save()
        after = self.envelope()
        self.assertNotEqual(before["salt"], after["salt"])
        self.assertNotEqual(before["nonce"], after["nonce"])
        self.assertEqual(before["master_hash"], after["master_hash"])

    def test_default_create_and_unsupported_open_do_not_overwrite_data(self):
        before = self.path.read_bytes()
        with self.assertRaises(VaultError):
            Vault.create(self.path, self.master)
        self.assertEqual(before, self.path.read_bytes())
        self.write({"version": 1})
        old = self.path.read_bytes()
        with self.assertRaisesRegex(VaultError, "Unsupported vault version"):
            Vault.open(self.path, self.master)
        self.assertEqual(old, self.path.read_bytes())

    def test_explicit_reset_replaces_verifier_and_all_entries(self):
        self.vault.add("old-account", "alice", "test-account-password")
        previous = self.envelope()
        other = self.path.parent / "other.vault.json"
        other.write_bytes(b"unrelated vault data")
        reset = Vault.create(self.path, "New demonstration master!", overwrite=True)
        self.assertEqual(reset.entries, {})
        self.assertEqual(Vault.open(self.path, "New demonstration master!").entries, {})
        with self.assertRaises(AuthenticationError):
            Vault.open(self.path, self.master)
        current = self.envelope()
        for field in ("master_hash", "salt", "nonce", "ciphertext"):
            self.assertNotEqual(previous[field], current[field])
        self.assertEqual(other.read_bytes(), b"unrelated vault data")

    def test_failed_reset_keeps_existing_vault(self):
        self.vault.add("old-account", "alice", "test-account-password")
        before = self.path.read_bytes()
        with patch(
            "storage.os.replace", side_effect=OSError("simulated write failure")
        ):
            with self.assertRaises(OSError):
                Vault.create(self.path, "New demonstration master!", overwrite=True)
        self.assertEqual(before, self.path.read_bytes())
        self.assertIn("old-account", Vault.open(self.path, self.master).entries)
        self.assertEqual([p.name for p in self.path.parent.iterdir()], ["vault.json"])

    def test_unicode_credentials_add_replace_remove_and_reopen(self):
        self.vault.add("学校.example", "叶同学", "密码🔐-test-only")
        self.vault.add("学校.example", "高同学", "replaced-test-password")
        reopened = Vault.open(self.path, self.master)
        self.assertEqual(reopened.entries["学校.example"]["username"], "高同学")
        self.assertNotIn("replaced-test-password", self.path.read_text())
        reopened.remove("学校.example")
        self.assertEqual(Vault.open(self.path, self.master).entries, {})

    def test_invalid_add_and_short_rotation_leave_vault_unchanged(self):
        before = self.path.read_bytes()
        for args in (("", "u", "p"), ("s", " ", "p"), ("s", "u", ""), ("s", None, "p")):
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    self.vault.add(*args)
                self.assertEqual(before, self.path.read_bytes())
                self.assertEqual(self.vault.entries, {})
        with self.assertRaises(ValueError):
            self.vault.change_master_password("short")
        self.assertEqual(before, self.path.read_bytes())

    def test_failed_save_keeps_disk_and_in_memory_state(self):
        self.vault.add("site", "user", "test-account")
        before = self.path.read_bytes()
        for operation in (
            lambda: self.vault.add("other", "u", "p"),
            lambda: self.vault.remove("site"),
            lambda: self.vault.change_master_password("new test master password!"),
        ):
            with patch(
                "storage.os.replace", side_effect=OSError("simulated write failure")
            ):
                with self.assertRaises(OSError):
                    operation()
            self.assertEqual(self.path.read_bytes(), before)
            self.assertEqual(self.vault.master_password, self.master)
            self.assertEqual(set(self.vault.entries), {"site"})
            self.assertEqual(
                [p.name for p in self.path.parent.iterdir()], ["vault.json"]
            )
        self.assertEqual(Vault.open(self.path, self.master).entries, self.vault.entries)

    def test_rotation_changes_verifier_and_preserves_entries(self):
        old_verifier = self.envelope()["master_hash"]
        self.vault.add("site", "user", "test-account")
        self.vault.change_master_password("New master password for testing!")
        self.assertNotEqual(old_verifier, self.envelope()["master_hash"])
        self.assertTrue(
            PasswordHasher().verify(
                self.envelope()["master_hash"], "New master password for testing!"
            )
        )
        with self.assertRaises(AuthenticationError):
            Vault.open(self.path, self.master)
        self.assertIn(
            "site", Vault.open(self.path, "New master password for testing!").entries
        )

    def test_generator_lengths_and_invalid_requests(self):
        for length in (12, 20, 24, 64, 4096):
            self.assertEqual(len(generate_password(length)), length)
        for length in (-1, 0, 11, 4097, True, "20"):
            with self.subTest(length=length):
                with self.assertRaises(ValueError):
                    generate_password(length)

    def test_missing_file_and_repr_do_not_expose_secrets(self):
        with self.assertRaises(VaultError):
            Vault.open(self.path.parent / "missing.json", self.master)
        self.vault.add("secret-site", "secret-user", "secret-account")
        representation = repr(self.vault)
        for secret in (self.master, "secret-account", "secret-user"):
            self.assertNotIn(secret, representation)

    @unittest.skipIf(os.name == "nt", "Unix permissions do not apply on Windows")
    def test_private_permissions_and_exclusive_creation(self):
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        with self.assertRaises(FileExistsError):
            atomic_write(self.path, b"replacement", overwrite=False)

    def test_oversize_input_is_rejected(self):
        with self.path.open("wb") as stream:
            stream.truncate(MAX_FILE_BYTES + 1)
        with self.assertRaises(AuthenticationError):
            Vault.open(self.path, self.master)


if __name__ == "__main__":
    unittest.main()
