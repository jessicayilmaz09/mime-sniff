# mime-sniff

Detect a content type from the leading bytes of a file, not from its extension.

```python
from mime_sniff import sniff, sniff_with_options

sniff(b"%PDF-1.4\n%stuff")            # -> "application/pdf"
sniff(b"hello, world", filename="a.txt")  # -> "text/plain" (extension fallback)

result = sniff_with_options(b"\x89PNG\r\n\x1a\n", filename="photo.jpg")
result.content_type      # -> "image/png"
result.from_extension    # -> False
```

## Why

Operating on uploaded bytes means you cannot trust a filename. This library
reads the first few bytes and matches them against a fixed table of magic
signatures. When the bytes match nothing, it falls back to the extension — but
only for text-like formats (`.txt`, `.csv`, `.json`, `.md`, etc.) that have no
reliable magic bytes of their own. Archive and image types are deliberately
absent from the extension table because the byte sniff already covers them and
an extension can lie.

`sniff` returns the content type string or `None`. `sniff_with_options` returns
a `SniffResult` whose `from_extension` flag tells you whether the answer came
from the bytes or from the filename. If you need to enforce that the result is
byte-derived, check that flag.

## Edge cases

- A UTF-8 BOM is stripped before matching, so BOM-prefixed XML and HTML are
  recognised.
- `sniff` accepts `bytes`, `bytearray`, and `memoryview`. Passing `str` raises
  `TypeError`.
- The extension fallback is case-insensitive on the extension but only fires
  when no byte signature matched.
