const actSecurity = {
    id: 'security', label: 'Security',
    x: 0.28, y: 0.72, r: 42,
    num: '07',
    title: 'Every attack has\na <em>barrier</em>.',
    body: `
      <p class="act-body cv-u-85f41527d93a">Security is not a feature. It is a series of walls, each independent of the others. An attacker must defeat all of them — not just one.</p>
      <div class="act-rule cv-u-480775b97f4e"></div>
      <p class="act-body cv-u-faa4089b0f47"><span class="tool-tip"><strong>Layer 1 — Air-gap.</strong><span class="tip-box">WiFi and Bluetooth radios are never initialized. Radio clocks gated at boot. USB OTG disabled. JTAG disabled. Data moves only through QR codes, SD card, and touchscreen.</span></span> No network stack. No electromagnetic channel in or out. Data moves through glass and plastic only.</p>
      <p class="act-body cv-u-257594085266"><span class="tool-tip"><strong>Layer 2 — Volatile keys.</strong><span class="tip-box">All key material lives in SRAM only. Mnemonic, master key, derived keys, signing nonces — all volatile. Power off and SRAM decays in milliseconds. Panic handler zeroizes RAM before halting.</span></span> Everything lives in RAM. Power off and it is gone — milliseconds. Not stored in flash. Not persisted anywhere. The panic handler wipes RAM even on a crash.</p>
      <p class="act-body cv-u-2df3c813a2bc"><span class="tool-tip"><strong>Layer 3 — Hardware Secure Boot.</strong><span class="tip-box">ESP32-S3 ROM verifies RSA-3072 signature against a digest burned permanently into eFuse. Only firmware signed with the matching private key can execute. Silicon-level guarantee.</span></span> On eFuse devices, the ROM — immutable silicon — verifies the firmware signature before any code runs. The RSA key digest is burned permanently. Only signed firmware executes.</p>
      <p class="act-body cv-u-7515b7fc2c3b"><span class="tool-tip"><strong>Layer 4 — Software verification.</strong><span class="tip-box">SHA-256 hash of the code segment computed at runtime. Compared against the build-time embedded hash. Schnorr signature of the hash verified against the developer's public key. Hash convergence ensures self-consistency.</span></span> Independent of Secure Boot. The firmware computes its own SHA-256 hash at every boot and verifies a Schnorr signature against the developer's public key. Tampered binary — boot halts.</p>
      <p class="act-body cv-u-58343cf5786a"><span class="tool-tip"><strong>Layer 5 — Rust memory safety.</strong><span class="tip-box">100% Rust, no_std. Ownership and borrow checker eliminate buffer overflows, use-after-free, null pointer dereference, uninitialized reads, double-free, data races — at compile time. Zero unsafe code in the entire signing path.</span></span> The entire signing path — parser, sighash, Schnorr, BIP32, address encoding — contains zero unsafe code. Malicious input triggers a panic and RAM wipe. Never arbitrary code execution.</p>
      <p class="act-body cv-u-3bae33251edd"><span class="tool-tip"><strong>Layer 6 — Encrypted backup.</strong><span class="tip-box">AES-256-GCM with PBKDF2 key derivation (100,000 iterations). BIP39 passphrase (25th word) creates a separate derivation — without it, only a decoy wallet is accessible. The passphrase exists only in your memory.</span></span> SD backups are AES-256-GCM encrypted. Even if someone decrypts the 24 words, the real wallet lives behind a passphrase that exists only in your memory. Without it — a decoy wallet.</p>
      <p class="act-body cv-u-dcf3763bfaa1"><span class="tool-tip"><strong>Layer 7 — Steganographic hiding.</strong><span class="tip-box">Encrypted seed hidden in JPEG EXIF metadata. The photo looks ordinary. Among thousands of files, nobody knows which one matters. No safe to crack, no metal plate to find.</span></span> The encrypted seed hides inside an ordinary JPEG photo on the SD card. Nobody knows which file matters. There is no safe to crack.</p>
      <div class="act-rule cv-u-7373ebbfc466"></div>
      <p class="act-body cv-u-d33167205a1c">Now — what can an attacker actually try?</p>`,
    diagram: `<div id="anim-wrap" class="cv-u-1cf17731c16c">

<svg id="anim-svg" width="100%" viewBox="0 0 660 620" xmlns="http://www.w3.org/2000/svg" class="cv-u-604449e974fd">
<defs>
  <marker id="arr2" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
    <path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
  </marker>

</defs>

<!-- Step 0: Legend -->
<g class="security-astep2 security-on" id="sa0">
  <text x="330" y="20" text-anchor="middle" class="security-h2 cv-u-7a4c5065e557">Attack Barriers</text>
  <rect x="40" y="40" width="14" height="14" rx="3" class="security-atk"/>
  <text x="62" y="51" class="security-s2">Attack vector</text>
  <rect x="180" y="40" width="14" height="14" rx="3" class="security-def"/>
  <text x="202" y="51" class="security-s2">Defense barrier</text>
  <rect x="340" y="40" width="14" height="14" rx="3" class="security-blk"/>
  <text x="362" y="51" class="security-s2">Blocked</text>
  <rect x="450" y="40" width="14" height="14" rx="3" class="security-usr"/>
  <text x="472" y="51" class="security-s2">Requires user action</text>
</g>

<!-- Step 1: Stolen SD card — 3 defense cards -->
<g class="security-astep2" id="sa1">
  <rect x="20" y="80" width="140" height="32" rx="6" class="security-atk"/>
  <text x="90" y="94" text-anchor="middle" class="security-t-red">Stolen SD card</text>
  <text x="90" y="106" text-anchor="middle" class="security-s2 cv-u-21484ff5b39c">seed backups</text>
  <path d="M160 96 L178 96" stroke="#993C1D" stroke-width="1.5" marker-end="url(#arr2)"/>
  <rect x="180" y="80" width="140" height="32" rx="6" class="security-def"/>
  <text x="250" y="94" text-anchor="middle" class="security-t-green">AES-256-GCM</text>
  <text x="250" y="106" text-anchor="middle" class="security-s2">PBKDF2 100K iter</text>
  <path d="M320 96 L338 96" stroke="#1D9E75" stroke-width="1.5" marker-end="url(#arr2)"/>
  <rect x="340" y="80" width="140" height="32" rx="6" class="security-def"/>
  <text x="410" y="94" text-anchor="middle" class="security-t-green">Stego hiding</text>
  <text x="410" y="106" text-anchor="middle" class="security-s2">in photo EXIF</text>
  <path d="M480 96 L498 96" stroke="#1D9E75" stroke-width="1.5" marker-end="url(#arr2)"/>
  <rect x="500" y="80" width="140" height="32" rx="6" class="security-def"/>
  <text x="570" y="94" text-anchor="middle" class="security-t-green">BIP39 passphrase</text>
  <text x="570" y="106" text-anchor="middle" class="security-s2">25th word, never stored</text>
  <rect x="535" y="117" width="72" height="20" rx="10" class="security-blk"/>
  <text x="571" y="131" text-anchor="middle" class="security-t-green cv-u-6e8bcfac8d63">BLOCKED</text>
</g>

<!-- Step 2: Physical access — device off -->
<g class="security-astep2" id="sa2">
  <rect x="20" y="160" width="140" height="32" rx="6" class="security-atk"/>
  <text x="90" y="174" text-anchor="middle" class="security-t-red">Physical access</text>
  <text x="90" y="186" text-anchor="middle" class="security-s2 cv-u-21484ff5b39c">device powered off</text>
  <path d="M160 176 L178 176" stroke="#993C1D" stroke-width="1.5" marker-end="url(#arr2)"/>
  <rect x="180" y="160" width="140" height="32" rx="6" class="security-def"/>
  <text x="250" y="174" text-anchor="middle" class="security-t-green">Volatile RAM</text>
  <text x="250" y="186" text-anchor="middle" class="security-s2">power off = zero</text>
  <rect x="215" y="197" width="72" height="20" rx="10" class="security-blk"/>
  <text x="251" y="211" text-anchor="middle" class="security-t-green cv-u-6e8bcfac8d63">BLOCKED</text>
</g>

<!-- Step 3: Physical access — device on -->
<g class="security-astep2" id="sa3">
  <rect x="20" y="240" width="140" height="32" rx="6" class="security-atk"/>
  <text x="90" y="254" text-anchor="middle" class="security-t-red">Physical access</text>
  <text x="90" y="266" text-anchor="middle" class="security-s2 cv-u-21484ff5b39c">device powered on</text>
  <path d="M160 256 L178 256" stroke="#993C1D" stroke-width="1.5" marker-end="url(#arr2)"/>
  <rect x="180" y="240" width="300" height="42" rx="6" class="security-usr"/>
  <text x="330" y="256" text-anchor="middle" class="security-t-amber">Keys in RAM — narrow window</text>
  <text x="330" y="268" text-anchor="middle" class="security-s2 cv-u-ccb849399142">needs lab gear $10K-$100K+ · JTAG disabled</text>
  <text x="330" y="278" text-anchor="middle" class="security-s2 cv-u-ccb849399142">mitigation: sign, then power off</text>
</g>

<!-- Step 4: Fake firmware -->
<g class="security-astep2" id="sa4">
  <rect x="20" y="310" width="140" height="32" rx="6" class="security-atk"/>
  <text x="90" y="324" text-anchor="middle" class="security-t-red">Fake firmware</text>
  <text x="90" y="336" text-anchor="middle" class="security-s2 cv-u-21484ff5b39c">phishing / fake repo</text>
  <path d="M160 326 L178 326" stroke="#993C1D" stroke-width="1.5" marker-end="url(#arr2)"/>
  <rect x="180" y="310" width="140" height="32" rx="6" class="security-def"/>
  <text x="250" y="324" text-anchor="middle" class="security-t-green">Docker verification</text>
  <text x="250" y="336" text-anchor="middle" class="security-s2 cv-u-127b564b4845">SHA-256 hash match</text>
  <path d="M320 326 L338 326" stroke="#1D9E75" stroke-width="1.5" marker-end="url(#arr2)"/>
  <rect x="340" y="310" width="140" height="32" rx="6" class="security-def"/>
  <text x="410" y="324" text-anchor="middle" class="security-t-green">eFuse Secure Boot</text>
  <text x="410" y="336" text-anchor="middle" class="security-s2">RSA-3072 in silicon</text>
  <path d="M480 326 L498 326" stroke="#1D9E75" stroke-width="1.5" marker-end="url(#arr2)"/>
  <rect x="500" y="310" width="140" height="32" rx="6" class="security-def"/>
  <text x="570" y="324" text-anchor="middle" class="security-t-green">Schnorr signature</text>
  <text x="570" y="336" text-anchor="middle" class="security-s2">boot-time hash check</text>
  <rect x="535" y="347" width="72" height="20" rx="10" class="security-blk"/>
  <text x="571" y="361" text-anchor="middle" class="security-t-green cv-u-6e8bcfac8d63">BLOCKED</text>
</g>

<!-- Step 5: Malware QR / SD input -->
<g class="security-astep2" id="sa5">
  <rect x="20" y="390" width="140" height="32" rx="6" class="security-atk"/>
  <text x="90" y="404" text-anchor="middle" class="security-t-red">Malware QR / SD</text>
  <text x="90" y="416" text-anchor="middle" class="security-s2 cv-u-21484ff5b39c">crafted data</text>
  <path d="M160 406 L178 406" stroke="#993C1D" stroke-width="1.5" marker-end="url(#arr2)"/>
  <rect x="180" y="390" width="140" height="32" rx="6" class="security-def"/>
  <text x="250" y="404" text-anchor="middle" class="security-t-green">Rust safe parsers</text>
  <text x="250" y="416" text-anchor="middle" class="security-s2">0 unsafe in signing</text>
  <path d="M320 406 L338 406" stroke="#1D9E75" stroke-width="1.5" marker-end="url(#arr2)"/>
  <rect x="340" y="390" width="140" height="32" rx="6" class="security-def"/>
  <text x="410" y="404" text-anchor="middle" class="security-t-green">Bounds checking</text>
  <text x="410" y="416" text-anchor="middle" class="security-s2">panic + RAM wipe</text>
  <rect x="375" y="427" width="72" height="20" rx="10" class="security-blk"/>
  <text x="411" y="441" text-anchor="middle" class="security-t-green cv-u-6e8bcfac8d63">BLOCKED</text>
</g>

<!-- Step 6: KasSee phishing -->
<g class="security-astep2" id="sa6">
  <rect x="20" y="470" width="140" height="32" rx="6" class="security-atk"/>
  <text x="90" y="484" text-anchor="middle" class="security-t-red">KasSee phishing</text>
  <text x="90" y="496" text-anchor="middle" class="security-s2 cv-u-21484ff5b39c">modifies TX in KasSee</text>
  <path d="M160 486 L178 486" stroke="#993C1D" stroke-width="1.5" marker-end="url(#arr2)"/>
  <rect x="180" y="470" width="180" height="32" rx="6" class="security-def"/>
  <text x="270" y="484" text-anchor="middle" class="security-t-green">On-device TX review</text>
  <text x="270" y="496" text-anchor="middle" class="security-s2">verify address on device</text>
  <path d="M360 486 L378 486" stroke="#1D9E75" stroke-width="1.5" marker-end="url(#arr2)"/>
  <rect x="380" y="470" width="140" height="32" rx="6" class="security-usr"/>
  <text x="450" y="490" text-anchor="middle" class="security-t-amber">User must verify</text>
</g>
</svg>

<div id="step-text" class="cv-u-2f3e61836490"></div>

<div class="cv-u-0ab292276143">
  <span id="step-label" class="cv-u-f9d3e60f606f">step 0 of 6</span>
  <div class="cv-u-0d76d82849c1">
    <button id="btn-back" disabled class="cv-u-5a1999cc6d79">← prev</button>
    <button id="btn-next" class="cv-u-ad8c79c8a8f3">next →</button>
  </div>
</div>
</div>`,
    satellites: []
  };
