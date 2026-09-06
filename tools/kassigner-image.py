#!/usr/bin/env python3
"""Convert KasSigner RGB565 little-endian hardware assets to/from PNG."""

import math
import re
import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError as exc:
    raise SystemExit("Pillow is required: python3 -m pip install Pillow") from exc

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ASSET_DIR = ROOT / "apps/signer-firmware/assets"


def raw_to_png(src, dst, width, height):
    data = Path(src).read_bytes()
    expected = width * height * 2
    if len(data) != expected:
        raise SystemExit(
            f"Wrong size: {len(data)} bytes; "
            f"expected {expected} for {width}x{height} RGB565"
        )

    rgb = bytearray(width * height * 3)
    for i in range(width * height):
        value = data[i * 2] | (data[i * 2 + 1] << 8)
        r5 = (value >> 11) & 0x1F
        g6 = (value >> 5) & 0x3F
        b5 = value & 0x1F
        rgb[i * 3] = (r5 * 255 + 15) // 31
        rgb[i * 3 + 1] = (g6 * 255 + 31) // 63
        rgb[i * 3 + 2] = (b5 * 255 + 15) // 31

    image = Image.frombytes("RGB", (width, height), bytes(rgb))
    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    image.save(dst)


def png_to_raw(src, dst, width, height):
    image = Image.open(src).convert("RGB")
    if image.size != (width, height):
        raise SystemExit(
            f"Wrong dimensions: {image.size[0]}x{image.size[1]}; "
            f"expected {width}x{height}"
        )

    out = bytearray()
    rgb = image.tobytes()
    for index in range(0, len(rgb), 3):
        r, g, b = rgb[index:index + 3]
        r5 = (r * 31 + 127) // 255
        g6 = (g * 63 + 127) // 255
        b5 = (b * 31 + 127) // 255
        value = (r5 << 11) | (g6 << 5) | b5
        # ImageRawLE<Rgb565> expects little-endian.
        out.append(value & 0xFF)
        out.append((value >> 8) & 0xFF)

    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    Path(dst).write_bytes(out)


def dimensions_from_raw(path: Path, source_png: Path | None = None) -> tuple[int, int]:
    """Resolve RAW dimensions without maintaining a duplicate asset manifest."""
    if source_png is not None and source_png.is_file():
        with Image.open(source_png) as image:
            return image.size

    match = re.search(r"(?:^|_)(\d+)x(\d+)(?:$|_)", path.stem)
    if match:
        return int(match.group(1)), int(match.group(2))

    match = re.search(r"_(\d+)$", path.stem)
    if match:
        side = int(match.group(1))
        if path.stat().st_size == side * side * 2:
            return side, side

    pixels, remainder = divmod(path.stat().st_size, 2)
    side = math.isqrt(pixels)
    if remainder == 0 and side * side == pixels:
        return side, side

    raise SystemExit(
        f"Cannot infer dimensions for {path}. "
        "Use a WIDTHxHEIGHT suffix or create the matching source PNG first."
    )


def batch_raw_to_png(asset_dir: Path) -> int:
    source_dir = asset_dir / "source"
    raw_files = sorted(asset_dir.glob("*.raw"))
    if not raw_files:
        raise SystemExit(f"No .raw assets found in {asset_dir}")
    for raw in raw_files:
        png = source_dir / f"{raw.stem}.png"
        width, height = dimensions_from_raw(raw, png)
        raw_to_png(raw, png, width, height)
        print(f"RAW -> PNG  {raw.relative_to(asset_dir)} -> source/{png.name} ({width}x{height})")
    print(f"Converted {len(raw_files)} RAW hardware assets to PNG.")
    return len(raw_files)


def batch_png_to_raw(asset_dir: Path) -> int:
    source_dir = asset_dir / "source"
    png_files = sorted(source_dir.glob("*.png"))
    if not png_files:
        raise SystemExit(f"No .png source assets found in {source_dir}")
    for png in png_files:
        with Image.open(png) as image:
            width, height = image.size
        raw = asset_dir / f"{png.stem}.raw"
        png_to_raw(png, raw, width, height)
        print(f"PNG -> RAW  source/{png.name} -> {raw.name} ({width}x{height})")
    print(f"Converted {len(png_files)} PNG hardware assets to RAW.")
    return len(png_files)


def usage() -> str:
    return (
        "Usage:\n"
        "  kassigner-image.py decode input.raw output.png WIDTH HEIGHT\n"
        "  kassigner-image.py encode input.png output.raw WIDTH HEIGHT\n"
        "  kassigner-image.py --raw [ASSET_DIR]   # all RAW inputs -> source/*.png\n"
        "  kassigner-image.py --png [ASSET_DIR]   # all source PNG inputs -> *.raw\n"
        "  kassigner-image.py create raw|png [ASSET_DIR]\n"
        "\n"
        "For batch flags, --raw/--png name the input format. For `create`, the\n"
        "argument names the requested output format. ASSET_DIR defaults to\n"
        "apps/signer-firmware/assets."
    )


def main(argv):
    if len(argv) >= 2 and argv[1] in {"--raw", "--png"}:
        if len(argv) > 3:
            raise SystemExit(usage())
        asset_dir = Path(argv[2]).resolve() if len(argv) == 3 else DEFAULT_ASSET_DIR
        if argv[1] == "--raw":
            batch_raw_to_png(asset_dir)
        else:
            batch_png_to_raw(asset_dir)
        return

    if len(argv) >= 2 and argv[1] == "create":
        if len(argv) not in {3, 4} or argv[2] not in {"raw", "png"}:
            raise SystemExit(usage())
        asset_dir = Path(argv[3]).resolve() if len(argv) == 4 else DEFAULT_ASSET_DIR
        if argv[2] == "raw":
            batch_png_to_raw(asset_dir)
        else:
            batch_raw_to_png(asset_dir)
        return

    if len(argv) != 6:
        raise SystemExit(usage())
    mode, src, dst, width, height = argv[1:]
    width = int(width)
    height = int(height)
    if width <= 0 or height <= 0:
        raise SystemExit("WIDTH and HEIGHT must be positive")
    if mode == "decode":
        raw_to_png(src, dst, width, height)
    elif mode == "encode":
        png_to_raw(src, dst, width, height)
    else:
        raise SystemExit("Mode must be decode or encode")


if __name__ == "__main__":
    main(sys.argv)
