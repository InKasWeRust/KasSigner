[KasSigner](../../README.md) › [Documentation](../README.md) › Hardware

# Hardware

## Supported targets

| Target | Code support | Qualification |
|---|---|---|
| M5Stack CoreS3 | Yes | **Hardware-tested** |
| M5Stack CoreS3 Lite | Shared M5Stack target | Not separately hardware-tested |
| Waveshare ESP32-S3-Touch-LCD-2 (OV2640/OV5640) | Yes | **Not hardware-tested** |
| Waveshare OV5640-AF variant | Yes | **Not hardware-tested** |

All targets use the ESP32-S3. Hardware support in source is not the same as release validation; see the warning in the root [README](../../README.md) and the release-readiness evidence gate in `../../qa/release/README.md`.

A community 3D-printable Waveshare case (snap-fit, LiPo 602030 cradle, USB-C access) is included under [`external/hardware/`](../../external/hardware/). Design by **Sandmann21** (GPL); see the folder README for attribution.


## CoreS3 production trust

M5Stack CoreS3 uses separate opt-in **`secure-provisioning`** (vendor + optional owner) and **`secure-owner-only`** (sole owner) firmware profiles for the owner-controlled **Pop It!** Secure Boot transition; normal `make release` firmware is non-destructive and omits the Pop It!/owner-authority UI and provisioning path. In dual mode, owner RSA-3072 enrollment before Pop It! is optional and vendor-signed applications remain authorized afterward. In owner-only mode enrollment is mandatory, the owner key becomes digest 0, the unused Secure Boot authority slots are revoked, and no vendor Secure Boot authority remains; subsequent application updates must satisfy the owner hardware authority. Development firmware simulates these workflows without eFuse writes. See [Pop It! and owner-authorized firmware](../security/POP_IT_SECURE_BOOT.md) and the [eFuse runbook](../EFUSE_RUNBOOK.md).

## References

- [ESP32-S3 Technical Reference Manual](https://www.espressif.com/sites/default/files/documentation/esp32-s3_technical_reference_manual_en.pdf): register-level peripheral documentation
- [ESP32-S3 Datasheet](https://www.espressif.com/sites/default/files/documentation/esp32-s3_datasheet_en.pdf): pinout, electrical characteristics, memory map
- [Waveshare ESP32-S3-Touch-LCD-2 Wiki](https://www.waveshare.com/wiki/ESP32-S3-Touch-LCD-2): board schematic, GPIO assignments, setup guide
- [M5Stack CoreS3 documentation](https://docs.m5stack.com/en/core/CoreS3): board specifications and hardware documentation
- [OV2640 Datasheet](https://www.uctronics.com/download/cam_module/OV2640DS.pdf): camera sensor registers and DVP interface
- [ST7789 Datasheet](https://www.newhavendisplay.com/appnotes/datasheets/LCDs/ST7789V.pdf): display controller commands, SPI protocol, initialization sequence
