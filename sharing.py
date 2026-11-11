"""Bonus A: encrypt one credential for a teammate's RSA public key."""

import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from password_manager import (
    AuthenticationError,
    Vault,
    VaultError,
    validate_new_password,
)
from storage import (
    atomic_write,
    canonical_json,
    decode_bytes,
    encode_bytes,
    read_bytes,
    read_json,
)

SHARE_AAD = b"Project2 shared credential v1\0"
SHARE_FIELDS = {"version", "key_wrap", "cipher", "wrapped_key", "nonce", "ciphertext"}
SHARE_ERROR = "Cannot decrypt share: wrong key/passphrase or modified file"


def _oaep() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=SHARE_AAD,
    )


def generate_keypair(
    private_path: str | Path, public_path: str | Path, passphrase: str
) -> None:
    """Only the encrypted private key stays on the recipient's machine."""
    validate_new_password(passphrase)
    private_path, public_path = Path(private_path), Path(public_path)
    if private_path.resolve() == public_path.resolve():
        raise VaultError("Private and public key paths must be different")
    if private_path.exists() or public_path.exists():
        raise VaultError("A key file already exists; choose new paths")
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    # 私钥用口令加密保存；队友之间只交换公钥。
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    atomic_write(private_path, private_pem, overwrite=False)
    try:
        atomic_write(public_path, public_pem, overwrite=False)
    except (OSError, ValueError):
        private_path.unlink()  # Roll back only the private file just created here.
        raise


def share_entry(
    vault: Vault, service: str, public_path: str | Path, output_path: str | Path
) -> None:
    if service not in vault.entries:
        raise VaultError(f"No entry for service: {service}")
    try:
        public_key = serialization.load_pem_public_key(read_bytes(public_path))
        if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 2048:
            raise ValueError("Expected an RSA public key of at least 2048 bits")
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise VaultError("Invalid RSA public key") from exc
    # RSA只加密随机AES密钥；AES-GCM加密单条记录，因此也能分享长密码。
    content_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    header = {
        "version": 1,
        "key_wrap": "RSA-OAEP-SHA256",
        "cipher": "AES-256-GCM",
        "wrapped_key": encode_bytes(public_key.encrypt(content_key, _oaep())),
        "nonce": encode_bytes(nonce),
    }
    entry = {"service": service, **vault.entries[service]}
    ciphertext = AESGCM(content_key).encrypt(
        nonce, canonical_json(entry), SHARE_AAD + canonical_json(header)
    )
    envelope = {**header, "ciphertext": encode_bytes(ciphertext)}
    atomic_write(
        output_path,
        json.dumps(envelope, indent=2).encode("utf-8") + b"\n",
        overwrite=False,
    )


def open_share(
    share_path: str | Path, private_path: str | Path, passphrase: str
) -> dict[str, str]:
    try:
        envelope = read_json(share_path)
        if set(envelope) != SHARE_FIELDS or type(envelope["version"]) is not int:
            raise ValueError("Invalid share fields")
        if (
            envelope["version"] != 1
            or envelope["key_wrap"] != "RSA-OAEP-SHA256"
            or envelope["cipher"] != "AES-256-GCM"
        ):
            raise ValueError("Unsupported share format")
        private_key = serialization.load_pem_private_key(
            read_bytes(private_path), password=passphrase.encode("utf-8")
        )
        if (
            not isinstance(private_key, rsa.RSAPrivateKey)
            or private_key.key_size < 2048
        ):
            raise ValueError("Expected an RSA private key")
        # 先用私钥还原AES密钥，再用AES-GCM验证并解密这条分享。
        wrapped_key = decode_bytes(envelope["wrapped_key"], private_key.key_size // 8)
        content_key = private_key.decrypt(wrapped_key, _oaep())
        if len(content_key) != 32:
            raise ValueError("Invalid content key")
        nonce = decode_bytes(envelope["nonce"], 12)
        ciphertext = decode_bytes(envelope["ciphertext"])
        header = {
            name: value for name, value in envelope.items() if name != "ciphertext"
        }
        plaintext = AESGCM(content_key).decrypt(
            nonce, ciphertext, SHARE_AAD + canonical_json(header)
        )
        entry = json.loads(plaintext)
        if not isinstance(entry, dict) or set(entry) != {
            "service",
            "username",
            "password",
        }:
            raise ValueError("Invalid shared entry")
        if any(not isinstance(value, str) or not value for value in entry.values()):
            raise ValueError("Invalid shared credential")
        return entry
    except OSError as exc:
        raise VaultError(f"Cannot read shared file or key: {exc.strerror}") from exc
    except (ValueError, TypeError, KeyError, InvalidTag, UnsupportedAlgorithm) as exc:
        raise AuthenticationError(SHARE_ERROR) from exc
