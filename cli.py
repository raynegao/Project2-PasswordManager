"""Command-line interface for the vault and the optional public-key share."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from argon2.exceptions import HashingError

from password_manager import Vault, VaultError, generate_password, validate_new_password
from sharing import generate_keypair, open_share, share_entry

DEFAULT_VAULT = Path("vault.json")


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AES-GCM encrypted password manager")
    parser.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="create an encrypted vault")

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
    keygen.add_argument("--private", type=Path, required=True)
    keygen.add_argument("--public", type=Path, required=True)
    share = commands.add_parser("share", help="encrypt one entry for a teammate")
    share.add_argument("service")
    share.add_argument("--public-key", type=Path, required=True)
    share.add_argument("--out", type=Path, required=True)
    receive = commands.add_parser("unshare", help="display a received encrypted entry")
    receive.add_argument("file", type=Path)
    receive.add_argument("--private-key", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "init":
            Vault.create(args.vault, confirm_password("New master password: "))
            print(f"Created encrypted vault: {args.vault}")
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
