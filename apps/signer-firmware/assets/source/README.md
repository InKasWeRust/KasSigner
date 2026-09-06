[KasSigner](../../../../README.md) › [Documentation](../../../../docs/README.md) › [Hardware](../../../../docs/hardware/HARDWARE.md) › Firmware assets

# Signer firmware source images

Editable PNG originals for generated RGB565 little-endian `.raw` assets live here.
The firmware consumes the generated `.raw` files one directory above.

The converter uses Pillow. Install it into the Python interpreter you will use for the conversion if needed:

```sh
python3 -m pip install Pillow
```

On Windows, use `python -m pip install Pillow` when `python` is your configured launcher.

Decode an existing hardware asset for editing:

```sh
python3 tools/kassigner-image.py decode \
  apps/signer-firmware/assets/kascoin_90.raw \
  apps/signer-firmware/assets/source/kascoin_90.png 90 90
```

Regenerate the firmware asset after editing:

```sh
python3 tools/kassigner-image.py encode \
  apps/signer-firmware/assets/source/kascoin_90.png \
  apps/signer-firmware/assets/kascoin_90.raw 90 90
```

Use the same commands for `kascoin_teal_90`. Commit both the editable PNG and generated raw asset when an image changes.

The same workflow applies to `icon_mute_90` and `icon_audio_90` when updating the CoreS3 home audio toggle assets.


## Batch conversion

The hardware-asset Make target has been removed. From the repository root, run the converter directly:

```sh
python3 tools/kassigner-image.py create png   # apps/signer-firmware/assets/*.raw -> assets/source/*.png
python3 tools/kassigner-image.py create raw   # assets/source/*.png -> apps/signer-firmware/assets/*.raw
```

On Windows, use `python` instead of `python3` if that is the installed launcher. The equivalent input-oriented flags are:

```sh
python3 tools/kassigner-image.py --raw   # RAW inputs -> PNG outputs
python3 tools/kassigner-image.py --png   # PNG inputs -> RAW outputs
```

For RAW files the converter resolves dimensions from an existing matching PNG, a `WIDTHxHEIGHT` filename suffix, a trailing square-size suffix such as `_90`, or an exact square pixel count. Non-square RAW assets therefore need an explicit `WIDTHxHEIGHT` filename (for example `logo_320x240.raw`) or a matching source PNG.

The Home `Connect` button uses `kas_see_56.png/.raw`, a firmware-sized derivative made directly from the supplied `kas-see.png` artwork. The full supplied `kas-see.png/.raw` remains in the asset set as the editable/source reference.
