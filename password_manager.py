"""Argon2id password verification and an AES-GCM encrypted credential vault."""

from __future__ import annotations

import json
import os
import secrets
import string
from dataclasses import dataclass, field
from pathlib import Path

from argon2 import PasswordHasher, extract_parameters
from argon2.exceptions import HashingError, InvalidHashError, VerificationError
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from storage import atomic_write, canonical_json, decode_bytes, encode_bytes, read_json

VERSION = 2
KDF_TIME_COST = 3
KDF_MEMORY_COST = 65536
KDF_PARALLELISM = 4
SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32
KDF_PARAMS = {
    "time_cost": KDF_TIME_COST,
    "memory_cost": KDF_MEMORY_COST,
    "parallelism": KDF_PARALLELISM,
    "hash_len": KEY_BYTES,
}
PASSWORD_HASHER = PasswordHasher(**KDF_PARAMS, salt_len=SALT_BYTES, type=Type.ID)
AAD = b"Yuchen-Haitian Password Manager v2\0"
AUTH_ERROR = "Wrong master password or the vault has been tampered with"


class VaultError(Exception):
    """Base class for safe, user-facing vault errors."""


class AuthenticationError(VaultError):
    """The password is wrong or the vault cannot be authenticated."""


def validate_new_password(password: str) -> None:
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError("The password must be at least 12 characters")


def derive_key(master_password: str, salt: bytes) -> bytes:
    validate_new_password(master_password)
    if not isinstance(salt, bytes) or len(salt) != SALT_BYTES:
        raise ValueError("The KDF salt must be 16 bytes")
    return hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        type=Type.ID,
        **KDF_PARAMS,
    )


def generate_password(length: int = 20) -> str:
    """Use OS-backed randomness for every choice and the final shuffle."""
    if type(length) is not int or not 12 <= length <= 4096:
        raise ValueError("Password length must be between 12 and 4096")
    classes = (
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        "!@#$%^&*()-_=+",
    )
    chars = [secrets.choice(group) for group in classes]
    alphabet = "".join(classes)
    chars.extend(secrets.choice(alphabet) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def _validate_hash(master_hash: str) -> None:
    if not isinstance(master_hash, str) or len(master_hash) > 256:
        raise ValueError("Invalid master-password hash")
    params = extract_parameters(master_hash)
    expected = (
        Type.ID,
        19,
        SALT_BYTES,
        KEY_BYTES,
        KDF_TIME_COST,
        KDF_MEMORY_COST,
        KDF_PARALLELISM,
    )
    actual = (
        params.type,
        params.version,
        params.salt_len,
        params.hash_len,
        params.time_cost,
        params.memory_cost,
        params.parallelism,
    )
    if actual != expected:
        # Do not let an untrusted file request arbitrary Argon2 memory or CPU.
        raise ValueError("Unsupported master-password hash parameters")


def _validate_entries(entries: dict) -> None:
    if not isinstance(entries, dict):
        raise ValueError("Invalid entries")
    for service, entry in entries.items():
        if not isinstance(service, str) or not service.strip():
            raise ValueError("Invalid service")
        if not isinstance(entry, dict) or set(entry) != {"username", "password"}:
            raise ValueError("Invalid credential")
        if not isinstance(entry["username"], str) or not entry["username"].strip():
            raise ValueError("Invalid username")
        if not isinstance(entry["password"], str) or not entry["password"]:
            raise ValueError("Invalid account password")


def _write_vault(
    path: Path,
    master_password: str,
    master_hash: str,
    entries: dict,
    *,
    overwrite: bool = True,
) -> None:
    _validate_entries(entries)
    _validate_hash(master_hash)
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    header = {
        "version": VERSION,
        "kdf": "Argon2id",
        "kdf_params": dict(KDF_PARAMS),
        "cipher": "AES-256-GCM",
        "master_hash": master_hash,
        "salt": encode_bytes(salt),
        "nonce": encode_bytes(nonce),
    }
    key = derive_key(master_password, salt)
    ciphertext = AESGCM(key).encrypt(
        nonce, canonical_json({"entries": entries}), AAD + canonical_json(header)
    )
    envelope = {**header, "ciphertext": encode_bytes(ciphertext)}
    atomic_write(
        path,
        json.dumps(envelope, indent=2).encode("utf-8") + b"\n",
        overwrite=overwrite,
    )


@dataclass
class Vault:
    path: Path
    master_password: str = field(repr=False)
    entries: dict[str, dict[str, str]] = field(repr=False)
    master_hash: str = field(repr=False)

    @classmethod
    def create(cls, path: str | Path, master_password: str) -> "Vault":
        vault_path = Path(path)
        if vault_path.exists():
            raise VaultError(f"Vault already exists: {vault_path}")
        validate_new_password(master_password)
        # PasswordHasher supplies a salt independent of the encryption salt.
        master_hash = PASSWORD_HASHER.hash(master_password)
        _write_vault(vault_path, master_password, master_hash, {}, overwrite=False)
        return cls(vault_path, master_password, {}, master_hash)

    @classmethod
    def open(cls, path: str | Path, master_password: str) -> "Vault":
        vault_path = Path(path)
        try:
            envelope = read_json(vault_path)
            if (
                type(envelope.get("version")) is not int
                or envelope["version"] != VERSION
            ):
                raise VaultError(
                    "Unsupported vault version; keep the original file and program"
                )
            fields = {
                "version",
                "kdf",
                "kdf_params",
                "cipher",
                "master_hash",
                "salt",
                "nonce",
                "ciphertext",
            }
            if set(envelope) != fields:
                raise ValueError("Invalid vault fields")
            if envelope["kdf"] != "Argon2id" or envelope["cipher"] != "AES-256-GCM":
                raise ValueError("Unsupported algorithm")
            if envelope["kdf_params"] != KDF_PARAMS:
                raise ValueError("Unsupported KDF parameters")
            _validate_hash(envelope["master_hash"])
            salt = decode_bytes(envelope["salt"], SALT_BYTES)
            nonce = decode_bytes(envelope["nonce"], NONCE_BYTES)
            ciphertext = decode_bytes(envelope["ciphertext"])
            if len(ciphertext) < 16:
                raise ValueError("Missing GCM authentication tag")
            PASSWORD_HASHER.verify(envelope["master_hash"], master_password)
            key = derive_key(master_password, salt)
            header = {
                name: value for name, value in envelope.items() if name != "ciphertext"
            }
            plaintext = AESGCM(key).decrypt(
                nonce, ciphertext, AAD + canonical_json(header)
            )
            data = json.loads(plaintext)
            if not isinstance(data, dict) or set(data) != {"entries"}:
                raise ValueError("Invalid decrypted vault")
            entries = data["entries"]
            _validate_entries(entries)
        except OSError as exc:
            raise VaultError(f"Cannot read vault: {exc.strerror}") from exc
        except (
            InvalidTag,
            InvalidHashError,
            VerificationError,
            HashingError,
            KeyError,
            ValueError,
            TypeError,
        ) as exc:
            raise AuthenticationError(AUTH_ERROR) from exc
        return cls(vault_path, master_password, entries, envelope["master_hash"])

    def save(self) -> None:
        _write_vault(self.path, self.master_password, self.master_hash, self.entries)

    def add(self, service: str, username: str, password: str) -> None:
        entries = {
            **self.entries,
            service: {"username": username, "password": password},
        }
        _write_vault(self.path, self.master_password, self.master_hash, entries)
        self.entries = entries

    def remove(self, service: str) -> None:
        if service not in self.entries:
            raise VaultError(f"No entry for service: {service}")
        entries = dict(self.entries)
        del entries[service]
        _write_vault(self.path, self.master_password, self.master_hash, entries)
        self.entries = entries

    def change_master_password(self, new_password: str) -> None:
        validate_new_password(new_password)
        master_hash = PASSWORD_HASHER.hash(new_password)
        _write_vault(self.path, new_password, master_hash, self.entries)
        self.master_password = new_password
        self.master_hash = master_hash
