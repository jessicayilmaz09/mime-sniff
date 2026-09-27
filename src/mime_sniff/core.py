from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SniffResult:
    """The outcome of a MIME sniff.

    ``content_type`` is the detected type, or ``None`` when nothing matched.
    ``from_extension`` is True when the result came from the supplied filename's
    extension rather than from the bytes themselves. Callers that need to trust
    the byte-level signal can ignore results where this flag is set.
    """

    content_type: str | None
    from_extension: bool = False


# Ordered by specificity: longest distinctive prefix first so that a shorter
# prefix cannot shadow a longer one that happens to share its leading bytes.
# Each entry is (byte_prefix, content_type). Prefixes are compared as raw
# bytes, so they are case-sensitive on purpose — the magic bytes we match are
# binary, not text.
_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"%PDF-", "application/pdf"),
    (b"PK\x03\x04", "application/zip"),
    (b"PK\x05\x06", "application/zip"),
    (b"PK\x07\x08", "application/zip"),
    (b"\x1f\x8b", "application/gzip"),
    (b"BZh", "application/x-bzip2"),
    (b"\xfd7zXZ\x00", "application/x-xz"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
    (b"Rar!\x1a\x07", "application/x-rar-compressed"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"BM", "image/bmp"),
    (b"II*\x00", "image/tiff"),
    (b"MM\x00*", "image/tiff"),
    (b"RIFF", "audio/wav"),
    (b"fLaC", "audio/flac"),
    (b"OggS", "application/ogg"),
    (b"ID3", "audio/mpeg"),
    (b"\xff\xfb", "audio/mpeg"),
    (b"\x00\x00\x01\x00", "image/x-icon"),
    (b"\x00\x00\x02\x00", "image/x-cursor"),
    (b"<?xml", "text/xml"),
    (b"<html", "text/html"),
    (b"<!DOCTYPE html", "text/html"),
    (b"<!doctype html", "text/html"),
    (b"<HTML", "text/html"),
    (b"<!--", "text/html"),
)

# A small, deliberately conservative extension map. We only include types
# where the extension is more trustworthy than a failed byte sniff — for
# example, plain text and CSV, which have no reliable magic bytes. We do not
# put image or archive types here because the byte sniff already covers them
# and an extension can lie.
_EXTENSION_MAP: dict[str, str] = {
    ".txt": "text/plain",
    ".csv": "text/csv",
    ".json": "application/json",
    ".html": "text/html",
    ".htm": "text/html",
    ".xml": "text/xml",
    ".css": "text/css",
    ".js": "text/javascript",
    ".md": "text/markdown",
}


def _strip_utf8_bom(data: bytes) -> bytes:
    """Drop a leading UTF-8 BOM so XML/HTML sniffing works on BOM-prefixed files."""
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:]
    return data


def _from_bytes(data: bytes) -> str | None:
    """Return the content type implied by the leading bytes, or None."""
    stripped = _strip_utf8_bom(data)
    for prefix, content_type in _SIGNATURES:
        if stripped.startswith(prefix):
            return content_type
    return None


def _from_extension(filename: str | None) -> str | None:
    """Return the content type implied by the filename extension, or None."""
    if not filename:
        return None
    dot = filename.rfind(".")
    if dot < 0:
        return None
    ext = filename[dot:].lower()
    return _EXTENSION_MAP.get(ext)


def sniff(data: bytes, filename: str | None = None) -> str | None:
    """Detect a content type from leading bytes.

    If ``filename`` is given and the bytes match no known signature, the
    extension is used as a fallback. This is the only case where the result is
    not derived from the bytes themselves.
    """
    result = sniff_with_options(data, filename=filename)
    return result.content_type


def sniff_with_options(
    data: bytes, filename: str | None = None
) -> SniffResult:
    """Like :func:`sniff`, but returns a :class:`SniffResult` that reports
    whether the answer came from the bytes or from the filename extension."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")
    data = bytes(data)
    content_type = _from_bytes(data)
    if content_type is not None:
        return SniffResult(content_type=content_type, from_extension=False)
    content_type = _from_extension(filename)
    if content_type is not None:
        return SniffResult(content_type=content_type, from_extension=True)
    return SniffResult(content_type=None, from_extension=False)
