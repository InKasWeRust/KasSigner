# ══════════════════════════════════════════════════════
#   Flash
# ══════════════════════════════════════════════════════
ask "Step 4 of 4 — Install on device" \
    "Sending firmware to your device.\n  Don't unplug the USB cable!"
if [ $? -ne 0 ]; then
    die "Flash step is required."
fi

# Re-check device
if [ ! -e "$PORT" ]; then
    PORT=$(ls /dev/cu.usbmodem* 2>/dev/null | head -1)
    [ -z "$PORT" ] && die "Device disconnected."
fi

note "Installing firmware..."
echo ""

FLASH_OK=1
if [ "$FLASH_MODE" = "elf" ]; then
    espflash flash --port "$PORT" "$BIN_FILE" 2>&1
    FLASH_OK=$?
else
    espflash write-bin --port "$PORT" 0x0 "$BIN_FILE" 2>&1
    FLASH_OK=$?
fi

if [ $FLASH_OK -ne 0 ]; then
    die "Flash failed." \
        "Unplug the device, wait 5 seconds, plug it back in, and try again."
fi

# ══════════════════════════════════════════════════════
#   Done!
# ══════════════════════════════════════════════════════
T=$SECONDS
M=$((T / 60))
S=$((T % 60))

echo ""
echo ""
echo -e "  ${G}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${X}"
echo -e "  ${G}${B}  KasSigner installed successfully!${X}"
echo -e "  ${G}  Total time: ${M}m ${S}s${X}"
echo -e "  ${G}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${X}"
echo ""
echo -e "  ${D}Your device is ready. You can close this window.${X}"
echo ""
