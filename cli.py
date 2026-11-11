"""Command-line interface for the vault and the optional public-key share."""

from __future__ import annotations

import argparse
import getpass
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from argon2.exceptions import HashingError

from password_manager import Vault, VaultError, generate_password, validate_new_password
from sharing import generate_keypair, open_share, share_entry

DEFAULT_VAULT = Path("vault.json")
DEFAULT_PRIVATE_KEY = Path("local/presentation-private.pem")
DEFAULT_PUBLIC_KEY = Path("local/presentation-public.pem")
DEFAULT_SHARE = Path("local/presentation.share.json")


def confirm_password(
    prompt: str, confirmation: str = "Confirm master password: "
) -> str:
    first = getpass.getpass(prompt)
    second = getpass.getpass(confirmation)
    if first != second:
        raise ValueError("Passwords do not match")
    validate_new_password(first)
    return first


def open_vault(path: Path) -> Vault:
    return Vault.open(path, getpass.getpass("Master password: "))


def reset_demo_vault(path: Path, master_password: str) -> None:
    """Reset the selected vault and local/; restore local/ if creation fails."""
    validate_new_password(master_password)
    vault_path = Path(path).absolute()
    local = Path.cwd() / "local"
    if local.is_symlink() or (local.exists() and not local.is_dir()):
        raise VaultError("local must be a real directory, not a file or symlink")
    had_local = local.exists()
    with tempfile.TemporaryDirectory(
        prefix=".pm-init-", suffix=".tmp", dir=local.parent
    ) as temporary:
        backup = Path(temporary) / "local"
        try:
            if had_local:
                local.rename(backup)
            local.mkdir(mode=0o700)
            if vault_path.is_relative_to(local):
                vault_path.parent.mkdir(parents=True, exist_ok=True)
            Vault.create(vault_path, master_password, overwrite=True)
        except BaseException:
            # Also restore old demo files after an interrupted initialization.
            if backup.exists():
                if local.exists():
                    shutil.rmtree(local)
                backup.rename(local)
            elif not had_local and local.exists():
                shutil.rmtree(local)
            raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AES-GCM encrypted password manager")
    parser.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser(
        "init", help="reset the selected vault and all files in local/ for a new demo"
    )

    add = commands.add_parser("add", help="add or replace a credential")
    add.add_argument("service")
    add.add_argument("username")
    add.add_argument("--generate", type=int, metavar="LENGTH")

    commands.add_parser("list", help="list service names and usernames")
    show = commands.add_parser("show", aliases=["get"], help="show one credential")
    show.add_argument("service")
    remove = commands.add_parser(
        "remove", aliases=["delete"], help="remove one credential"
    )
    remove.add_argument("service")
    commands.add_parser("change-master", help="rotate the master password")
    generate = commands.add_parser(
        "generate", aliases=["gen"], help="generate a strong password"
    )
    generate.add_argument("--length", type=int, default=20)

    keygen = commands.add_parser("keygen", help="create a teammate's RSA key pair")
    keygen.add_argument("--private", type=Path, default=DEFAULT_PRIVATE_KEY)
    keygen.add_argument("--public", type=Path, default=DEFAULT_PUBLIC_KEY)
    share = commands.add_parser("share", help="encrypt one entry for a teammate")
    share.add_argument("service")
    share.add_argument("--public-key", type=Path, default=DEFAULT_PUBLIC_KEY)
    share.add_argument("--out", type=Path, default=DEFAULT_SHARE)
    receive = commands.add_parser("unshare", help="display a received encrypted entry")
    receive.add_argument("file", type=Path, nargs="?", default=DEFAULT_SHARE)
    receive.add_argument("--private-key", type=Path, default=DEFAULT_PRIVATE_KEY)
    commands.add_parser("test", help="run the project's full test suite")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "test":
            return subprocess.run(
                [sys.executable, "-m", "unittest", "-v"],
                cwd=Path(__file__).resolve().parent,
                check=False,
            ).returncode
        if args.command == "init":
            resetting = args.vault.exists()
            master_password = confirm_password("New master password: ")
            reset_demo_vault(args.vault, master_password)
            action = "Reset" if resetting else "Created"
            print(f"{action} encrypted vault: {args.vault}")
            print("Reset local demo files: local")
            return 0
        if args.command in ("generate", "gen"):
            print(generate_password(args.length))
            return 0
        if args.command == "keygen":
            passphrase = confirm_password(
                "Private-key passphrase: ", "Confirm private-key passphrase: "
            )
            generate_keypair(args.private, args.public, passphrase)
            print(f"Created encrypted private key: {args.private}")
            print(f"Public key to exchange: {args.public}")
            return 0
        if args.command == "unshare":
            entry = open_share(
                args.file, args.private_key, getpass.getpass("Private-key passphrase: ")
            )
            print(f"Service: {entry['service']}")
            print(f"Username: {entry['username']}")
            print(f"Password: {entry['password']}")
            return 0

        vault = open_vault(args.vault)
        if args.command == "add":
            if args.generate is None:
                password = getpass.getpass("Account password: ")
            else:
                password = generate_password(args.generate)
            vault.add(args.service, args.username, password)
            print(f"Saved: {args.service}")
            if args.generate is not None:
                print(f"Generated password: {password}")
        elif args.command == "list":
            for service in sorted(vault.entries):
                print(f"{service}: {vault.entries[service]['username']}")
        elif args.command in ("show", "get"):
            entry = vault.entries.get(args.service)
            if entry is None:
                raise VaultError(f"No entry for service: {args.service}")
            print(f"Username: {entry['username']}")
            print(f"Password: {entry['password']}")
        elif args.command in ("remove", "delete"):
            vault.remove(args.service)
            print(f"Removed: {args.service}")
        elif args.command == "change-master":
            vault.change_master_password(confirm_password("New master password: "))
            print("Master password changed and vault re-encrypted")
        elif args.command == "share":
            share_entry(vault, args.service, args.public_key, args.out)
            print(f"Encrypted one entry: {args.out}")
        return 0
    except (VaultError, ValueError, OSError, HashingError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
