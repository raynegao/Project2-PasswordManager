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

    def test_bad_confirmation_reinitialization_and_missing_files(self):
        self.run_command(
            ["init"],
            [("New master password: ", MASTER), ("Confirm master password: ", ROTATED)],
            expected=1,
        )
        self.assertFalse((self.folder / "vault.json").exists())
        self.initialize()
        before = (self.folder / "vault.json").read_bytes()
        self.run_command(
            ["init"],
            [("New master password: ", MASTER), ("Confirm master password: ", MASTER)],
            expected=1,
        )
        self.assertEqual(before, (self.folder / "vault.json").read_bytes())
        self.run_command(
            ["--vault", "missing.json", "list"],
            [("Master password: ", MASTER)],
            expected=1,
        )

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


if __name__ == "__main__":
    unittest.main()
