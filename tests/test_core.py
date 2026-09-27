import unittest

from mime_sniff import sniff, sniff_with_options, SniffResult


class TestSniff(unittest.TestCase):
    def test_pdf_magic(self):
        self.assertEqual(sniff(b"%PDF-1.4\n%stuff"), "application/pdf")

    def test_zip_magic(self):
        self.assertEqual(sniff(b"PK\x03\x04"), "application/zip")

    def test_gzip_magic(self):
        self.assertEqual(sniff(b"\x1f\x8b\x08\x00"), "application/gzip")

    def test_png_magic(self):
        self.assertEqual(
            sniff(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"), "image/png"
        )

    def test_jpeg_magic(self):
        self.assertEqual(sniff(b"\xff\xd8\xff\xe0"), "image/jpeg")

    def test_gif87_magic(self):
        self.assertEqual(sniff(b"GIF87a"), "image/gif")

    def test_gif89_magic(self):
        self.assertEqual(sniff(b"GIF89a"), "image/gif")

    def test_xml_with_utf8_bom(self):
        data = b"\xef\xbb\xbf<?xml version=\"1.0\"?>"
        self.assertEqual(sniff(data), "text/xml")

    def test_html_doctype_lowercase(self):
        self.assertEqual(sniff(b"<!DOCTYPE html>"), "text/html")

    def test_html_comment_prefix(self):
        self.assertEqual(sniff(b"<!-- comment --><html>"), "text/html")

    def test_unknown_bytes_return_none(self):
        self.assertIsNone(sniff(b"\x00\x01\x02\x03 random noise"))

    def test_empty_bytes_return_none(self):
        self.assertIsNone(sniff(b""))

    def test_extension_fallback(self):
        self.assertEqual(sniff(b"hello, world", filename="notes.txt"), "text/plain")

    def test_extension_not_used_when_bytes_match(self):
        # Bytes win over extension even when the extension is wrong.
        self.assertEqual(
            sniff(b"\x89PNG\r\n\x1a\n", filename="photo.jpg"), "image/png"
        )

    def test_extension_case_insensitive(self):
        self.assertEqual(sniff(b"x", filename="DATA.CSV"), "text/csv")

    def test_no_extension_returns_none_when_bytes_unknown(self):
        self.assertIsNone(sniff(b"plain text with no magic", filename="README"))


class TestSniffWithOptions(unittest.TestCase):
    def test_from_bytes_flag(self):
        result = sniff_with_options(b"%PDF-1.4")
        self.assertIsInstance(result, SniffResult)
        self.assertEqual(result.content_type, "application/pdf")
        self.assertFalse(result.from_extension)

    def test_from_extension_flag(self):
        result = sniff_with_options(b"1,2,3\n", filename="data.csv")
        self.assertEqual(result.content_type, "text/csv")
        self.assertTrue(result.from_extension)

    def test_none_result_flag(self):
        result = sniff_with_options(b"\x00\x01\x02")
        self.assertIsNone(result.content_type)
        self.assertFalse(result.from_extension)

    def test_rejects_str(self):
        with self.assertRaises(TypeError):
            sniff_with_options("not bytes")  # type: ignore[arg-type]

    def test_accepts_bytearray(self):
        result = sniff_with_options(bytearray(b"%PDF-1.4"))
        self.assertEqual(result.content_type, "application/pdf")

    def test_accepts_memoryview(self):
        result = sniff_with_options(memoryview(b"%PDF-1.4"))
        self.assertEqual(result.content_type, "application/pdf")


if __name__ == "__main__":
    unittest.main()
