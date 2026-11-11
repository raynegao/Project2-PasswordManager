"""Argon2id password verification and an AES-GCM encrypted credential vault."""

import json
import os
import secrets
import string
from dataclasses import dataclass, field
from pathlib import Path

from argon2 import Parameters, PasswordHasher, extract_parameters
from argon2.exceptions import HashingError, InvalidHashError, VerificationError
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from storage import atomic_write, canonical_json, decode_bytes, encode_bytes, read_json

VERSION = 2
SALT_BYTES = 16
NONCE_BYTES = 12
KDF_PARAMS = {
    "time_cost": 3,
    "memory_cost": 65536,  # KiB，即64 MiB内存。
    "parallelism": 4,
    "hash_len": 32,
}
PASSWORD_HASHER = PasswordHasher(**KDF_PARAMS, salt_len=SALT_BYTES, type=Type.ID)
HASH_PARAMS = Parameters(type=Type.ID, version=19, salt_len=SALT_BYTES, **KDF_PARAMS)
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
    """主密码加独立盐，派生32字节AES密钥；密钥不写入文件。"""
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
    """用secrets选取四类字符并安全洗牌，避免可预测的random。"""
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
    # 验证前限制文件中的Argon2参数，防止被改成巨大的内存或计算开销。
    if extract_parameters(master_hash) != HASH_PARAMS:
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
    # 每次保存都生成新盐和nonce，全部账号一起加密。
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
    # 文件头可公开，但作为AAD参与认证，改动头部也会使解密失败。
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
    def create(
        cls, path: str | Path, master_password: str, *, overwrite: bool = False
    ) -> "Vault":
        """Create an empty vault; the demo CLI explicitly allows replacement."""
        vault_path = Path(path)
        if vault_path.exists() and not overwrite:
            raise VaultError(f"Vault already exists: {vault_path}")
        validate_new_password(master_password)
        # 主密码只存Argon2id验证串；它的盐与AES密钥派生用的盐独立。
        master_hash = PASSWORD_HASHER.hash(master_password)
        _write_vault(vault_path, master_password, master_hash, {}, overwrite=overwrite)
        return cls(vault_path, master_password, {}, master_hash)

    @classmethod
    def open(cls, path: str | Path, master_password: str) -> "Vault":
        vault_path = Path(path)
        try:
            # 1. 先检查文件结构、算法及Argon2参数，再处理密码。
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
            # 2. 验证主密码；正确后才派生AES密钥。
            PASSWORD_HASHER.verify(envelope["master_hash"], master_password)
            key = derive_key(master_password, salt)
            header = {
                name: value for name, value in envelope.items() if name != "ciphertext"
            }
            # 3. GCM先验证认证标签，成功后才返回账号明文。
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

    def add(self, service: str, username: str, password: str) -> None:
        entries = {
            **self.entries,
            service: {"username": username, "password": password},
        }
        # 写入成功后再更新内存，避免写失败时内存和磁盘不一致。
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
