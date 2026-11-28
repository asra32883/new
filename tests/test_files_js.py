"""The attachment metadata stripper (app/static/js/files.js) run under Node against real images."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

PIL = pytest.importorskip("PIL.Image")
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
JS = Path(__file__).parent.parent / "app" / "static" / "js" / "files.js"

RUNNER = """
const fs = require('fs'); const F = require(process.argv[1]);
const out = {};
for (const p of process.argv.slice(2)) {
  const r = F.clean(new Uint8Array(fs.readFileSync(p)));
  out[p] = { mime: r.mime, cleaned: r.cleaned, ok: r.ok };
  fs.writeFileSync(p + '.clean', r.bytes);
}
console.log(JSON.stringify(out));
"""


def _images(tmp_path):
    from PIL import Image, PngImagePlugin
    im = Image.new("RGB", (40, 30), (200, 30, 30))
    ex = Image.Exif(); ex[0x0112] = 6; ex[0x010F] = "SecretCameraMaker"
    gps = ex.get_ifd(0x8825); gps[1] = "N"; gps[2] = (51.0, 30.0, 12.0)
    paths = {}
    paths["jpg"] = tmp_path / "a.jpg"; im.save(paths["jpg"], exif=ex, comment=b"private comment")
    info = PngImagePlugin.PngInfo(); info.add_text("Author", "SecretAuthor")
    paths["png"] = tmp_path / "a.png"; im.save(paths["png"], pnginfo=info)
    paths["webp"] = tmp_path / "a.webp"; im.save(paths["webp"], exif=ex.tobytes(), xmp=b"<x>SecretXmp</x>")
    paths["gif"] = tmp_path / "a.gif"; Image.new("P", (10, 10)).save(paths["gif"], comment=b"SecretGifComment")
    return paths


def test_metadata_is_removed_images_still_decode_and_orientation_survives(tmp_path):
    from PIL import Image
    paths = _images(tmp_path)
    res = json.loads(subprocess.run(["node", "-e", RUNNER, str(JS), *map(str, paths.values())], capture_output=True, text=True, check=True).stdout)
    for kind, p in paths.items():
        assert res[str(p)]["cleaned"] and res[str(p)]["ok"], kind
        raw = Path(str(p) + ".clean").read_bytes()
        for secret in (b"Secret", b"GPS", b"private comment", b"Exif\x00\x00II", b"Exif\x00\x00MM\x00*\x00\x00\x00\x08\x00\x02"):
            assert secret not in raw, (kind, secret)
        img = Image.open(Path(str(p) + ".clean")); img.load()
    assert Image.open(Path(str(paths["jpg"]) + ".clean")).getexif().get(0x0112) == 6      # sideways photos stay upright


def test_malformed_and_unknown_inputs(tmp_path):
    bad = tmp_path / "bad.jpg"; bad.write_bytes(bytes([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x01]))
    other = tmp_path / "x.bin"; other.write_bytes(b"not an image at all")
    res = json.loads(subprocess.run(["node", "-e", RUNNER, str(JS), str(bad), str(other)], capture_output=True, text=True, check=True).stdout)
    assert res[str(bad)]["ok"] is False and res[str(bad)]["cleaned"] is False      # looks like an image, cannot be cleaned: refused by the UI
    assert res[str(other)] == {"mime": None, "cleaned": False, "ok": True}          # not an image: sent as it is, and the UI says so


def test_file_names_are_sanitised():
    out = subprocess.run(["node", "-e", "const F=require(process.argv[1]);console.log(JSON.stringify([F.safeName('../x/pa\\u202Essw\\u0000d.exe'),F.safeName(''),F.safeName('a'.repeat(300)+'.jpeg').length]))", str(JS)],
                         capture_output=True, text=True, check=True).stdout
    assert json.loads(out) == ["passwd.exe", "file", 120]
