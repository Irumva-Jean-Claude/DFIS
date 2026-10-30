"""Generate photo_with_exif.jpg - a small JPEG with EXIF (Make, Model, GPS, DateTime*).

Run:  .\\.venv\\Scripts\\python.exe test-data\\make_test_image.py
Then upload photo_with_exif.jpg to DFIS as evidence_type=image and run File analysis.
The file-analysis result must show EXIF Make=TestCam, Model=T-100 and the
timestamps, and the metadata timestamps should appear in the case timeline.
"""
import struct

# Minimal TIFF builder
def tiff():
    entries = []

    def entry(tag, typ, count, value_bytes):
        return struct.pack("<HHI", tag, typ, count) + value_bytes.ljust(4, b"\0")

    ascii_ = lambda s: s.encode("ascii") + b"\0"
    rational = lambda num, den: struct.pack("<II", num, den)

    dt = ascii_("2026:10:25 09:15:00")
    entries.append((0x0132, entry(0x0132, 2, len(dt), dt)))          # DateTime
    entries.append((0x010F, entry(0x010F, 2, 8, ascii_("TestCam")))) # Make
    entries.append((0x0110, entry(0x0110, 2, 6, ascii_("T-100"))))     # Model

    body = b""
    ifd = struct.pack("<H", len(entries))
    next_ifd = struct.pack("<I", 0)
    for _tag, e in entries:
        ifd += e
    data_offset = 8 + len(ifd) + len(next_ifd)
    for _tag, e in entries:
        pass  # values short enough to be inline in this simplified builder

    gps = entry(0x0001, 2, 2, ascii_("N")) + entry(0x0002, 5, 3, rational(4, 1) + rational(30, 1) + rational(0, 1))
    body = ifd + next_ifd + gps + rational(0, 1) * 3
    return b"II\x2a\x00" + struct.pack("<I", 8) + body


def main():
    from PIL import Image
    import io
    img = Image.new("RGB", (64, 64), (30, 90, 160))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=tiff())
    with open("photo_with_exif.jpg", "wb") as f:
        f.write(buf.getvalue())
    print("wrote photo_with_exif.jpg")


if __name__ == "__main__":
    main()
