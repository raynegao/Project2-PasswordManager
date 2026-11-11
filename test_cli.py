"""Run the actual CLI in separate processes, with terminal password prompts."""

import json
import os
import select
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cli import reset_demo_vault
from password_manager import Vault

try:
    import pty
except ImportError:
    pty = None


CLI = str(Path(__file__).with_name("cli.py"))
MASTER = "CLI test master password only!"
ROTATED = "CLI rotated master password only!"
ACCOUNT = "CLI account password only!"


def run_cli(folder, args, answers=()):
    """Use a real PTY on macOS/Linux; a pipe fallback keeps Windows usable."""
    command = [sys.executable, CLI, *args]
    if pty is None:
        result = subprocess.run(
            command,
            cwd=folder,
            input="\n".join(value for _, value in answers) + "\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
        return result.returncode, result.stdout
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(folder)
        os.execv(sys.executable, command)
    output = b""
    cursor = 0
    index = 0
    deadline = time.monotonic() + 30
    try:
        while time.monotonic() < deadline:
            if select.select([fd], [], [], 0.1)[0]:
                try:
                    chunk = os.read(fd, 8192)
                except OSError:
                    break
                if not chunk:
                    break
                output += chunk
            if index < len(answers):
                prompt, value = answers[index]
                found = output.find(prompt.encode(), cursor)
                if found >= 0:
                    os.write(fd, value.encode("utf-8") + b"\n")
                    cursor = found + len(prompt)
                    index += 1
        else:
            os.kill(pid, 9)
            raise AssertionError(f"CLI timed out: {args}")
        _, status = os.waitpid(pid, 0)
    finally:
        os.close(fd)
    if index != len(answers):
        raise AssertionError(
            f"Missing CLI prompt: {args}; {output.decode(errors='replace')}"
        )
    return os.waitstatus_to_exitcode(status), output.decode(errors="replace")


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)

    def run_command(self, args, answers=(), expected=0):
        code, output = run_cli(self.folder, args, answers)
        self.assertEqual(code, expected, output)
        self.assertNotIn("Traceback", output)
        return output

    def initialize(self, prefix=()):
        return self.run_command(
            [*prefix, "init"],
            [("New master password: ", MASTER), ("Confirm master password: ", MASTER)],
        )

    def test_complete_basic_workflow_and_password_rotation(self):
        output = self.initialize()
        self.assertNotIn(MASTER, output)
        output = self.run_command(
            ["add", "example", "alice"],
            [("Master password: ", MASTER), ("Account password: ", ACCOUNT)],
        )
        self.assertNotIn(ACCOUNT, output)
        unlock = [("Master password: ", MASTER)]
        self.assertIn("example: alice", self.run_command(["list"], unlock))
        self.assertIn(ACCOUNT, self.run_command(["get", "example"], unlock))
        self.run_command(
            ["show", "example"], [("Master password: ", "wrong password!")], expected=1
        )
        self.run_command(
            ["change-master"],
            unlock
            + [
                ("New master password: ", ROTATED),
                ("Confirm master password: ", ROTATED),
            ],
        )
        self.run_command(["list"], unlock, expected=1)
        new_unlock = [("Master password: ", ROTATED)]
        self.assertIn(ACCOUNT, self.run_command(["show", "example"], new_unlock))
        self.run_command(["delete", "example"], new_unlock)
        self.run_command(["show", "example"], new_unlock, expected=1)

    def test_custom_vault_and_generated_password(self):
        prefix = ["--vault", "custom.vault.json"]
        self.initialize(prefix)
        output = self.run_command(
            prefix + ["add", "generated", "bob", "--generate", "24"],
            [("Master password: ", MASTER)],
        )
        generated = output.split("Generated password: ")[-1].strip()
        self.assertEqual(len(generated), 24)
        self.assertIn(
            generated,
            self.run_command(
                prefix + ["show", "generated"], [("Master password: ", MASTER)]
            ),
        )
        self.assertFalse((self.folder / "vault.json").exists())
        self.assertEqual(len(self.run_command(["gen", "--length", "64"]).strip()), 64)
        self.run_command(["generate", "--length", "11"], expected=1)
        self.run_command(
            prefix + ["add", "zero", "bob", "--generate", "0"],
            [("Master password: ", MASTER)],
            expected=1,
        )

    def test_bad_confirmation_and_missing_files(self):
        self.run_command(
            ["init"],
            [("New master password: ", MASTER), ("Confirm master password: ", ROTATED)],
            expected=1,
        )
        self.assertFalse((self.folder / "vault.json").exists())
        self.initialize()
        self.run_command(
            ["--vault", "missing.json", "list"],
            [("Master password: ", MASTER)],
            expected=1,
        )

    def test_reinitialization_resets_entries_and_master_password(self):
        prefix = ["--vault", "demo.vault.json"]
        self.initialize(prefix)
        self.run_command(
            prefix + ["add", "old-account", "alice"],
            [("Master password: ", MASTER), ("Account password: ", ACCOUNT)],
        )
        output = self.run_command(
            prefix + ["init"],
            [
                ("New master password: ", ROTATED),
                ("Confirm master password: ", ROTATED),
            ],
        )
        self.assertIn("Reset encrypted vault", output)
        self.assertNotIn(
            "old-account",
            self.run_command(prefix + ["list"], [("Master password: ", ROTATED)]),
        )
        self.run_command(
            prefix + ["get", "old-account"],
            [("Master password: ", ROTATED)],
            expected=1,
        )
        self.run_command(prefix + ["list"], [("Master password: ", MASTER)], expected=1)
        self.run_command(
            prefix + ["add", "new-account", "bob"],
            [("Master password: ", ROTATED), ("Account password: ", ACCOUNT)],
        )
        self.assertIn(
            "new-account: bob",
            self.run_command(prefix + ["list"], [("Master password: ", ROTATED)]),
        )

    def test_invalid_reset_input_keeps_existing_vault(self):
        self.initialize()
        path = self.folder / "vault.json"
        before = path.read_bytes()
        marker = self.folder / "local/keep-private.pem"
        marker.write_text("Existing demo file")
        for first, second in ((ROTATED, MASTER), ("short", "short")):
            with self.subTest(password_length=len(first)):
                self.run_command(
                    ["init"],
                    [
                        ("New master password: ", first),
                        ("Confirm master password: ", second),
                    ],
                    expected=1,
                )
                self.assertEqual(before, path.read_bytes())
                self.assertEqual(marker.read_text(), "Existing demo file")
                self.run_command(["list"], [("Master password: ", MASTER)])

    @unittest.skipIf(pty is None, "Requires an interactive terminal")
    def test_cancelled_reset_prompt_keeps_existing_vault(self):
        self.initialize()
        path = self.folder / "vault.json"
        before = path.read_bytes()
        marker = self.folder / "local/keep-private.pem"
        marker.write_text("Existing demo file")
        output = self.run_command(
            ["init"], [("New master password: ", "\x03")], expected=1
        )
        self.assertIn("Cancelled", output)
        self.assertEqual(before, path.read_bytes())
        self.assertEqual(marker.read_text(), "Existing demo file")
        self.run_command(["list"], [("Master password: ", MASTER)])

    def test_corrupt_files_and_header_changes_are_clean_errors(self):
        self.initialize()
        path = self.folder / "vault.json"
        baseline = json.loads(path.read_text())
        cases = ["[]", "null", "{"]
        for field, value in (
            ("salt", "eA=="),
            ("kdf", "Brgon2id"),
            ("cipher", "BES-256-GCM"),
        ):
            envelope = dict(baseline)
            envelope[field] = value
            cases.append(json.dumps(envelope))
        for content in cases:
            with self.subTest(content=content[:40]):
                path.write_text(content)
                self.run_command(["list"], [("Master password: ", MASTER)], expected=1)

    def test_bonus_key_generation_share_and_receive(self):
        self.initialize()
        self.run_command(
            ["add", "school", "alice"],
            [("Master password: ", MASTER), ("Account password: ", ACCOUNT)],
        )
        passphrase = "CLI recipient passphrase only!"
        output = self.run_command(
            [
                "keygen",
                "--private",
                "recipient.pem",
                "--public",
                "recipient-public.pem",
            ],
            [
                ("Private-key passphrase: ", passphrase),
                ("Confirm private-key passphrase: ", passphrase),
            ],
        )
        self.assertNotIn(passphrase, output)
        self.run_command(
            [
                "share",
                "school",
                "--public-key",
                "recipient-public.pem",
                "--out",
                "school.share.json",
            ],
            [("Master password: ", MASTER)],
        )
        output = self.run_command(
            ["unshare", "school.share.json", "--private-key", "recipient.pem"],
            [("Private-key passphrase: ", passphrase)],
        )
        self.assertIn(ACCOUNT, output)
        self.run_command(
            ["unshare", "school.share.json", "--private-key", "recipient.pem"],
            [("Private-key passphrase: ", "wrong passphrase!")],
            expected=1,
        )

    def test_help_and_invalid_command(self):
        self.assertIn("share", self.run_command(["--help"]))
        self.run_command(["nonexistent-command"], expected=2)

    def test_bonus_short_commands_use_default_paths(self):
        (self.folder / "local").mkdir()
        prefix = ["--vault", "local/rehearsal.vault.json"]
        self.initialize(prefix)
        self.run_command(
            prefix + ["add", "github", "alice"],
            [("Master password: ", MASTER), ("Account password: ", ACCOUNT)],
        )
        # Reuse the existing generator for the private key's passphrase.
        passphrase = self.run_command(["gen", "--length", "24"]).strip()
        self.assertEqual(len(passphrase), 24)
        prompts = [
            ("Private-key passphrase: ", passphrase),
            ("Confirm private-key passphrase: ", passphrase),
        ]
        output = self.run_command(["keygen"], prompts)
        self.assertNotIn(passphrase, output)
        self.assertIn("local/presentation-public.pem", output)
        private_path = self.folder / "local/presentation-private.pem"
        public_path = self.folder / "local/presentation-public.pem"
        before = (private_path.read_bytes(), public_path.read_bytes())
        self.assertTrue(before[0].startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY"))
        self.run_command(prefix + ["share", "github"], [("Master password: ", MASTER)])
        share_path = self.folder / "local/presentation.share.json"
        self.assertNotIn(ACCOUNT, share_path.read_text())
        output = self.run_command(
            ["unshare"], [("Private-key passphrase: ", passphrase)]
        )
        self.assertIn("Service: github", output)
        self.assertIn("Username: alice", output)
        self.assertIn(ACCOUNT, output)
        self.run_command(
            ["unshare"], [("Private-key passphrase: ", "wrong passphrase!")], expected=1
        )
        self.run_command(["keygen"], prompts, expected=1)
        self.assertEqual(before, (private_path.read_bytes(), public_path.read_bytes()))

    def test_init_clears_all_local_data_and_recreates_nested_vault(self):
        prefix = ["--vault", "local/nested/demo.vault.json"]
        self.initialize(prefix)
        self.run_command(
            prefix + ["add", "github", "alice"],
            [("Master password: ", MASTER), ("Account password: ", ACCOUNT)],
        )
        local = self.folder / "local"
        for name in (
            "other.vault.json",
            "old-private.pem",
            "old-public.pem",
            "old.share.json",
            "nested/notes.txt",
        ):
            (local / name).write_text("Old demo data")
        outside = self.folder / "keep-source.py"
        outside.write_text("# keep project files\n")
        output = self.run_command(
            prefix + ["init"],
            [
                ("New master password: ", ROTATED),
                ("Confirm master password: ", ROTATED),
            ],
        )
        self.assertIn("Reset local demo files: local", output)
        self.assertEqual(
            {str(p.relative_to(local)) for p in local.rglob("*") if p.is_file()},
            {"nested/demo.vault.json"},
        )
        self.assertEqual(
            Vault.open(local / "nested/demo.vault.json", ROTATED).entries, {}
        )
        self.assertEqual(outside.read_text(), "# keep project files\n")
        self.run_command(prefix + ["list"], [("Master password: ", MASTER)], expected=1)
        self.assertFalse(list(self.folder.glob(".pm-init-*")))

    def test_failed_init_restores_all_local_data_and_selected_vault(self):
        for relative in ("vault.json", "local/demo.vault.json"):
            with self.subTest(vault=relative):
                path = self.folder / relative
                self.initialize(["--vault", relative])
                local = self.folder / "local"
                marker = local / "recipient-private.pem"
                marker.write_text("Existing demo private key")
                before = path.read_bytes()
                with (
                    patch("cli.Path.cwd", return_value=self.folder),
                    patch(
                        "storage.os.replace",
                        side_effect=PermissionError("Simulated write failure"),
                    ),
                ):
                    with self.assertRaises(PermissionError):
                        reset_demo_vault(path, ROTATED)
                self.assertEqual(path.read_bytes(), before)
                self.assertEqual(marker.read_text(), "Existing demo private key")
                self.assertEqual(Vault.open(path, MASTER).entries, {})
                self.assertFalse(list(self.folder.glob(".pm-init-*")))

    def test_interrupted_init_restores_local_data(self):
        self.initialize(["--vault", "local/demo.vault.json"])
        path = self.folder / "local/demo.vault.json"
        before = path.read_bytes()
        marker = self.folder / "local/saved.share.json"
        marker.write_text("Existing demo share")
        with (
            patch("cli.Path.cwd", return_value=self.folder),
            patch("cli.Vault.create", side_effect=KeyboardInterrupt),
        ):
            with self.assertRaises(KeyboardInterrupt):
                reset_demo_vault(path, ROTATED)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(marker.read_text(), "Existing demo share")
        self.assertFalse(list(self.folder.glob(".pm-init-*")))

    @unittest.skipIf(
        os.name == "nt", "Creating symlinks may require Windows privileges"
    )
    def test_init_does_not_follow_local_symlinks(self):
        self.initialize()
        outside = self.folder / "outside"
        outside.mkdir()
        marker = outside / "keep.txt"
        marker.write_text("Keep data outside local")
        local = self.folder / "local"
        (local / "shortcut").symlink_to(outside, target_is_directory=True)
        self.initialize()
        self.assertEqual(marker.read_text(), "Keep data outside local")
        self.assertFalse((local / "shortcut").exists())
        local.rmdir()
        local.symlink_to(outside, target_is_directory=True)
        before = (self.folder / "vault.json").read_bytes()
        self.run_command(
            ["init"],
            [
                ("New master password: ", ROTATED),
                ("Confirm master password: ", ROTATED),
            ],
            expected=1,
        )
        self.assertTrue(local.is_symlink())
        self.assertEqual(marker.read_text(), "Keep data outside local")
        self.assertEqual((self.folder / "vault.json").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
