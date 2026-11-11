"""Small file helpers shared by the vault and the sharing bonus."""

import base64
import json
import os
import tempfile
from pathlib import Path

MAX_FILE_BYTES = 8 * 1024 * 1024


def encode_bytes(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def decode_bytes(value: str, length: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise ValueError("Expected a Base64 string")
    decoded = base64.b64decode(value, validate=True)
    if length is not None and len(decoded) != length:
        raise ValueError("Invalid field length")
    return decoded


def canonical_json(value: dict) -> bytes:
    """同样的JSON内容产生同样的字节，供文件头的AAD认证使用。"""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _unique_keys(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def read_bytes(path: str | Path) -> bytes:
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("File is too large")
    return data


def read_json(path: str | Path) -> dict:
    data = json.loads(read_bytes(path), object_pairs_hook=_unique_keys)
    if not isinstance(data, dict):
        raise ValueError("Expected a JSON object")
    return data


def atomic_write(path: str | Path, data: bytes, *, overwrite: bool = True) -> None:
    """先写私有临时文件，再一次替换目标，避免失败时留下半个文件。"""
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("File is too large")
    path = Path(path)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(temporary, path)
        else:
            # Fail if the destination exists, unlike os.replace.
            os.link(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
