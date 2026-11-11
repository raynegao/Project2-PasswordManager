import json
import string
import tempfile
import unittest
from pathlib import Path

from password_manager import AuthenticationError, Vault, generate_password


class PasswordManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "vault.json"
        self.master = "correct horse battery staple"

    def tearDown(self):
        self.temp.cleanup()

    def test_create_add_and_reopen(self):
        vault = Vault.create(self.path, self.master)
        vault.add("example.com", "alice", "S3cret-account-password!")
        reopened = Vault.open(self.path, self.master)
        self.assertEqual(reopened.entries["example.com"]["username"], "alice")
        self.assertEqual(reopened.entries["example.com"]["password"], "S3cret-account-password!")
        self.assertNotIn("S3cret-account-password!", self.path.read_text(encoding="utf-8"))

    def test_wrong_master_password_is_rejected(self):
        Vault.create(self.path, self.master)
        with self.assertRaises(AuthenticationError):
            Vault.open(self.path, "incorrect password")

    def test_ciphertext_tampering_is_rejected(self):
        Vault.create(self.path, self.master)
        envelope = json.loads(self.path.read_text(encoding="utf-8"))
        ciphertext = envelope["ciphertext"]
        envelope["ciphertext"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
        self.path.write_text(json.dumps(envelope), encoding="utf-8")
        with self.assertRaises(AuthenticationError):
            Vault.open(self.path, self.master)

    def test_change_master_password_invalidates_old_password(self):
        vault = Vault.create(self.path, self.master)
        vault.add("school", "yuchen", "account-password")
        vault.change_master_password("a completely different master password")
        with self.assertRaises(AuthenticationError):
            Vault.open(self.path, self.master)
        reopened = Vault.open(self.path, "a completely different master password")
        self.assertIn("school", reopened.entries)

    def test_generated_password_has_required_classes(self):
        password = generate_password(24)
        self.assertEqual(len(password), 24)
        self.assertTrue(any(c in string.ascii_lowercase for c in password))
        self.assertTrue(any(c in string.ascii_uppercase for c in password))
        self.assertTrue(any(c in string.digits for c in password))
        self.assertTrue(any(c in "!@#$%^&*()-_=+" for c in password))


if __name__ == "__main__":
    unittest.main()
