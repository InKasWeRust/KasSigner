# ══════════════════════════════════════════════════════
#   Connect device
# ══════════════════════════════════════════════════════
ask "Step 1 of 4 — Plug in your device" \
    "Connect the Waveshare ESP32-S3 to your Mac with a USB-C cable."
if [ $? -ne 0 ]; then
    die "You need to connect the device to continue."
fi

PORT=$(ls /dev/cu.usbmodem* 2>/dev/null | head -1)
if [ -z "$PORT" ]; then
    note "Looking for device..."
    for i in 1 2 3 4 5; do
        sleep 2
        PORT=$(ls /dev/cu.usbmodem* 2>/dev/null | head -1)
        [ -n "$PORT" ] && break
        echo -e "  ${D}  Waiting... ($((i*2))s)${X}"
    done
fi
if [ -z "$PORT" ]; then
    die "Device not found." \
        "Try a different USB-C cable — some only charge, no data."
fi
ok "Device found at $PORT"

# ══════════════════════════════════════════════════════
#   Erase device
# ══════════════════════════════════════════════════════
ask "Step 2 of 4 — Erase device" \
    "This clears the device so we can install fresh firmware.\n  All existing data on the device will be removed."
if [ $? -ne 0 ]; then
    die "Erase is required before installing new firmware."
fi

ERASE_OK=1
if command -v espflash >/dev/null 2>&1; then
    espflash erase-flash --port "$PORT" 2>&1
    ERASE_OK=$?
else
    die "espflash is required to erase the device.\n  Run: cargo install espflash"
fi

if [ $ERASE_OK -ne 0 ]; then
    die "Erase failed." \
        "Unplug the device, wait 5 seconds, plug it back in, and try again."
fi

sleep 2
ok "Device erased"
