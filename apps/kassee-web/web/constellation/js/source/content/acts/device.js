const actDevice = {
    id: 'device', label: 'KasSigner',
    x: 0.42, y: 0.50, r: 52,
    num: '05',
    title: '<em>KasSigner</em>\nenters the chain.',
    body: `
      <p class="act-body cv-u-85f41527d93a"><strong>KasSigner</strong> runs on an <span class="tool-tip">ESP32-S3<span class="tip-box">A dual-core 240MHz microcontroller by Espressif. 512KB SRAM, 8MB PSRAM, built-in USB. Runs bare-metal Rust — no operating system, no background processes. Around $25 for the Waveshare board.</span></span> — a consumer microcontroller with a touchscreen and a camera. No operating system. No vendor libraries anywhere near the signing path.</p>
      <div class="act-rule cv-u-ffac2d6c2723"></div>
      <p class="act-body cv-u-066fd9ca019f">It is <strong>not a hardware wallet</strong>. No secure element. No persistent storage. Everything lives in RAM and is wiped the moment you power off. Your backup is your seed words, not the device. What it is: an <strong>air-gapped signing device</strong>. WiFi and Bluetooth disabled permanently at boot. Data moves only through QR codes, SD card, and touchscreen.</p>
      <div class="act-rule cv-u-0aa541c7d500"></div>
      <p class="act-body cv-u-d2bd64e45664">Power it on and you see four cards. That is the entire interface.</p>
      <p class="act-body cv-u-fa469dbd52df"><span class="tool-tip"><strong>Scan</strong><span class="tip-box">Point the camera at a QR code. Unsigned transactions from KasSee, SeedQR imports, public keys for multisig — the device detects and decodes automatically, including multi-frame animated QR codes.</span></span> — the camera. Scan unsigned transactions from KasSee, import seeds via SeedQR, receive public keys for multisig. Multi-frame animated QR codes decoded automatically.</p>
      <p class="act-body cv-u-d3f650a25cf0"><span class="tool-tip"><strong>Seeds</strong><span class="tip-box">Up to 16 seed slots in RAM. Each shows a fingerprint, type (12-word, 24-word, xprv, raw key), and passphrase indicator. Tap to activate. From here: view addresses, sign transactions, export kpub or xprv, show seed words, create backups.</span></span> — your wallets. Up to 16 slots in RAM, each with its own fingerprint. View addresses, sign transactions, export your public key to KasSee, create encrypted SD backups, steganographic JPEG backups, or paper SeedQR cards.</p>
      <p class="act-body cv-u-e753952120c6"><span class="tool-tip"><strong>Tools</strong><span class="tip-box">Create new seeds from hardware entropy or dice rolls. Import seeds by typing words, scanning QR, or loading from SD card. BIP85 child mnemonics. Multisig address creation. Message signing. Steganographic export.</span></span> — creation and import. Generate a new seed from hardware entropy or from physical dice rolls you can verify yourself. Import seeds and keys from SD, QR, or hex. Derive BIP85 child wallets. Create multisig addresses. Sign arbitrary messages to prove you control a key.</p>
      <p class="act-body cv-u-df4c9f1bb32e"><span class="tool-tip"><strong>Settings</strong><span class="tip-box">Display brightness, SD card formatting, device information, firmware version and hash.</span></span> — display brightness, SD card, firmware info.</p>
      <div class="act-rule cv-u-3ec95397eb29"></div>
      <p class="act-body cv-u-2c16998ff44c">The firmware is signed and verified at every boot — <strong>KasSigner</strong> checks its own integrity before it lets you do anything. Builds are reproducible. You can compile from source and confirm the binary matches what is running on the device, byte for byte.</p>
      <div class="act-rule cv-u-7ec00dbcbb3c"></div>
      <p class="act-body cv-u-cc75a4692f0f">And there is one more thing <strong>KasSigner</strong> is — a teacher. Every step is visible. You see the seed become keys. You see keys become addresses. You see UTXOs selected, transactions built, sighashes computed, signatures produced. Nothing is hidden behind an abstraction. Use it offline, disconnected from everything, and learn how this technology actually works. That is not a side effect. It is the point.</p>
      <blockquote class="act-quote cv-u-44d39bc56617">Four cards. No menus to memorize.<br>A signing device. A learning machine.<br>They talk through KasSee.</blockquote>`,
    satellites: []
  };
