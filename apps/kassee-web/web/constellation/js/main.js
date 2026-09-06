
// ── touch device detection ─────────────────────────────
document.addEventListener('touchstart', function onFirstTouch() {
  document.body.classList.add('touch-device');
  document.removeEventListener('touchstart', onFirstTouch);
}, { passive: true });
// also detect on load for iPad
if ('ontouchstart' in window || navigator.maxTouchPoints > 0) {
  document.body.classList.add('touch-device');
}

// ── cursor ──────────────────────────────────────────────
const cur = document.getElementById('cur');
const isTouch = document.body.classList.contains('touch-device');
cur.style.opacity = '0';
if (isTouch) cur.style.display = 'none';
let MX = -200, MY = -200;
document.addEventListener('mousemove', e => {
  if (document.body.classList.contains('touch-device')) return;
  MX = e.clientX; MY = e.clientY;
  cur.style.left = MX + 'px';
  cur.style.top  = MY + 'px';
  if (cur.style.opacity === '0') {
    cur.style.opacity = '1';
    document.body.classList.add('moved');
  }
}, { once: false });
document.addEventListener('mousedown', () => cur.classList.add('dn'));
document.addEventListener('mouseup',   () => cur.classList.remove('dn'));

// ── screen manager ───────────────────────────────────────
function show(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('on'));
  document.getElementById(id).classList.add('on');
  const inAct = id === 's-act';
  document.getElementById('mini-map').classList.toggle('on', inAct);
  document.getElementById('hint').style.opacity = inAct ? '1' : '0';
  // hide constellation canvas when reading an act
  document.getElementById('c').style.opacity = inAct ? '0' : '1';
}

// ── act data ─────────────────────────────────────────────
const actEthos = {
    id: 'ethos', label: 'Ethos',
    x: 0.50, y: 0.12, r: 44,
    num: '01',
    title: 'Security. Scalability.\n<em>Decentralization.</em>',
    body: `
      <p class="act-body cv-u-85f41527d93a">In 2008, Satoshi Nakamoto published a paper and solved a problem nobody thought was solvable — commoditized data, no middle man. Proof of work. A chain of blocks. One block at a time, one miner wins, everyone else throws their work away.</p>
      <p class="act-body cv-u-ffac2d6c2723">And at the heart of it — miners. Miners are nodes. They validate transactions, enforce the rules, and build the chain. No miners, no consensus. No consensus, no network. No network, nothing. Every block you see exists because someone spent energy to produce it. That energy is the security. That is what proof of work means.</p>
      <p class="act-body cv-u-066fd9ca019f">It worked. But it came with a constraint that everyone accepted and nobody questioned: you can only have two out of three. <strong>Security, scalability, decentralization</strong> — pick two. That became the blockchain trilemma. And for fifteen years, every project either accepted the trade-off or cheated it — proof of stake, layer 2s, trusted validators, pre-mined tokens.</p>
      <div class="act-rule cv-u-0aa541c7d500"></div>
      <p class="act-body cv-u-d2bd64e45664">The scaling research started there. Yonatan Sompolinsky and his collaborators published PHANTOM, then SPECTRE, then GHOSTDAG — a series of protocols that replaced the chain with a <strong>DAG</strong>. Instead of discarding competing blocks, order all of them. No orphans. No wasted proof of work. The result was Kaspa — ten blocks per second, same Nakamoto-class security, fully decentralized.</p>
      <p class="act-body cv-u-c0a52b239ee5">That is Kaspa. Pure proof of work. No premine. No foundation allocation. No venture capital with preferred terms. Fair launch — like Bitcoin was supposed to be, at the speed Bitcoin could never reach.</p>
      <div class="act-rule cv-u-e5868a42ffe1"></div>
      <p class="act-body cv-u-6428576618bc">SeedSigner showed that you do not need a $200 hardware wallet to sign Bitcoin transactions. An open-source device on a $25 board. <strong>KasSigner</strong> brings that to Kaspa.</p>
      <p class="act-body cv-u-18bd494c6fe0">The code is open. Every line auditable. Builds reproducible. Not a product looking for a market — a tool built for people who believe sovereignty should not be a premium feature.</p>
      <blockquote class="act-quote cv-u-3ec95397eb29">We build in the open<br>because sovereignty cannot be built in secret.</blockquote>`,
    satellites: []
  };
const actMultisig = {
    id: 'multisig', label: 'Multisig',
    x: 0.85, y: 0.25, r: 38,
    num: '02',
    title: 'First air-gapped multisig\non <em>Kaspa mainnet</em>.',
    body: `
      <p class="act-body cv-u-85f41527d93a">One key signs. What if you need two? Or three out of five?</p>
      <p class="act-body cv-u-480775b97f4e"><span class="tool-tip">Multisig<span class="tip-box">M-of-N multi-signature. Multiple co-signers each contribute a public key to create a shared address. M of the N keys must sign to spend funds. A 2-of-3 setup means any two of three keyholders can authorize a transaction — no single point of failure.</span></span> is the answer. <strong>KasSigner</strong> supports M-of-N multisig — the first air-gapped implementation on the Kaspa network.</p>
      <div class="act-rule cv-u-fd571900bea5"></div>
      <p class="act-body cv-u-0aa541c7d500">Each co-signer has their own <strong>KasSigner</strong> device with their own seed. They exchange public keys via QR — no network, no server, no coordinator. The device derives a <span class="tool-tip">P2SH<span class="tip-box">Pay-to-Script-Hash. The funds are locked to a script that requires M valid signatures from the N registered public keys. The address is derived from the script hash, not from a single public key.</span></span> multisig address from the combined keys. Funds sent to that address require M signatures to spend.</p>
      <p class="act-body cv-u-0dc73b5f729d">To spend, KasSee builds the unsigned transaction. Device A scans and signs — partial signature, 1 of M. The partial goes to Device B via QR. Device B adds its signature — 2 of M. Done. Fully signed. KasSee broadcasts.</p>
      <div class="act-rule cv-u-1b36ca052773"></div>
      <p class="act-body cv-u-7515b7fc2c3b">No single device holds enough power to move funds. No single person can be coerced into signing. No single seed, if compromised, loses anything. This is how organizations, families, and paranoid individuals protect real wealth.</p>
      <p class="act-body cv-u-58343cf5786a">The co-signing can happen device-to-device — point one camera at the other screen — or relayed through KasSee. Either way, private keys never leave their device. The air-gap holds for every signer.</p>
      <blockquote class="act-quote cv-u-3bae33251edd">March 31, 2026.<br>The first ever air-gapped multisig transaction<br>signed with KasSigner on Kaspa mainnet.</blockquote>`,
    satellites: []
  };
const actChain = {
    id: 'chain', label: 'The chain',
    x: 0.88, y: 0.50, r: 40,
    num: '03',
    title: 'Every transaction\nis a <em>link</em>.',
    body: `
      <p class="act-body cv-u-85f41527d93a">Every Kaspa transaction starts with a question: what do you own?</p>
      <p class="act-body cv-u-480775b97f4e">The answer lives on the network — in what are called unspent outputs, or UTXOs. Think of them as sealed envelopes, each one containing an amount and a lock. The lock is your public key. Only your private key can open it.</p>
      <div class="act-rule cv-u-428f1ba92009"></div>
      <p class="act-body cv-u-257594085266"><strong>KasSee</strong> is the part that talks to the network. It knows your public key, finds your envelopes, and builds the transaction — who you are sending to, how much, what change comes back to you. But it cannot sign anything. It has no access to your private key.</p>
      <p class="act-body cv-u-2df3c813a2bc">KasSee runs locally on your machine as a WebAssembly application — files you can verify against a hash published in the repository. No server, no cloud, nothing phoning home. And the node it connects to is your choice — by default a public one, but you can point it at your own. Your node, your view of what you own.</p>
      <div class="act-rule cv-u-1b36ca052773"></div>
      <p class="act-body cv-u-7515b7fc2c3b">To sign, KasSee needs two things: the transaction it just built, and the details of the envelope being opened — the amount and the lock. It packages both and sends them to <strong>KasSigner</strong> as a QR code.</p>
      <p class="act-body cv-u-58343cf5786a">KasSigner receives the package. It reads the amount and the destination. It shows them to you on its own screen — a screen that has never touched the internet. You confirm. Then and only then it signs, using the private key that has never left the device.</p>
      <p class="act-body cv-u-3bae33251edd">The signature goes back to KasSee via QR. KasSee sends the completed transaction to the network. The network checks the signature against the lock. If it matches, the envelope opens. The funds move.</p>
      <blockquote class="act-quote cv-u-dcf3763bfaa1">What you see on the device screen<br>is what gets signed.<br>Cryptographically enforced.</blockquote>`,
    diagram: `<div id="anim-wrap" class="cv-u-476c676f5a86">

<svg id="anim-svg" width="100%" viewBox="-20 0 720 800" xmlns="http://www.w3.org/2000/svg" class="cv-u-604449e974fd">
<defs>
  <marker id="arr" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
    <path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
  </marker>

</defs>

<g class="chain-astep chain-on" id="st0">
  <rect x="30" y="20" width="148" height="34" rx="6" class="chain-b-teal"/>
  <text x="104" y="41" text-anchor="middle" dominant-baseline="central" class="chain-t-teal cv-u-294bcb81e01b">Kaspa DAG (node)</text>
  <rect x="190" y="20" width="110" height="34" rx="6" class="chain-b-gray"/>
  <text x="245" y="41" text-anchor="middle" dominant-baseline="central" class="chain-h">Kassee</text>
  <rect x="314" y="20" width="160" height="34" rx="6" class="chain-b-purple"/>
  <text x="394" y="41" text-anchor="middle" dominant-baseline="central" class="chain-t-purple">KasSigner</text>
  <rect x="488" y="20" width="162" height="34" rx="6" class="chain-b-teal"/>
  <text x="569" y="41" text-anchor="middle" dominant-baseline="central" class="chain-t-teal cv-u-294bcb81e01b">Kaspa DAG (node)</text>
</g>

<g class="chain-astep" id="st1">
  <rect x="30" y="68" width="148" height="22" rx="11" class="chain-chip-a"/>
  <text x="104" y="83" text-anchor="middle" dominant-baseline="central" class="chain-t-amber">kpub on UTXO</text>
  <rect x="190" y="68" width="110" height="22" rx="11" class="chain-chip-a"/>
  <text x="245" y="83" text-anchor="middle" dominant-baseline="central" class="chain-t-amber">kpub → address</text>
  <rect x="314" y="68" width="160" height="22" rx="11" class="chain-chip-c"/>
  <text x="394" y="83" text-anchor="middle" dominant-baseline="central" class="chain-t-coral">kpriv — never leaves</text>
  <rect x="488" y="68" width="162" height="22" rx="11" class="chain-chip-a"/>
  <text x="569" y="83" text-anchor="middle" dominant-baseline="central" class="chain-t-amber">kpub on UTXO</text>
</g>

<g class="chain-astep" id="st2">
  <rect x="190" y="110" width="110" height="66" rx="6" class="chain-b-gray"/>
  <text x="245" y="122" text-anchor="middle" dominant-baseline="central" class="chain-h">User initiates</text>
  <text x="245" y="138" text-anchor="middle" dominant-baseline="central" class="chain-s">builds</text>
  <text x="245" y="154" text-anchor="middle" dominant-baseline="central" class="chain-s">unsigned tx</text>
</g>

<g class="chain-astep" id="st3">
  <line x1="245" y1="176" x2="245" y2="182" class="chain-conn" stroke="#2a3a2a" marker-end="url(#arr)"/>
  <rect x="190" y="184" width="110" height="44" rx="6" class="chain-b-gray"/>
  <text x="245" y="202" text-anchor="middle" dominant-baseline="central" class="chain-h">Fetch UTXO</text>
  <text x="245" y="218" text-anchor="middle" dominant-baseline="central" class="chain-s">value + kpub</text>
  <path d="M190 200 L178 200" fill="none" stroke="#1D9E75" stroke-width="1.5" marker-end="url(#arr)"/>
  <rect x="30" y="184" width="148" height="44" rx="6" class="chain-b-teal"/>
  <text x="104" y="202" text-anchor="middle" dominant-baseline="central" class="chain-h">UTXO entry</text>
  <text x="104" y="218" text-anchor="middle" dominant-baseline="central" class="chain-t-teal cv-u-c28fa1ae60e2">value + kpub</text>
  <path d="M178 218 L190 218" fill="none" stroke="#1D9E75" stroke-width="1.5" marker-end="url(#arr)"/>
  <rect x="190" y="232" width="110" height="22" rx="11" class="chain-chip-a"/>
  <text x="245" y="247" text-anchor="middle" dominant-baseline="central" class="chain-t-amber">kpub received</text>
</g>

<g class="chain-astep" id="st4">
  <line x1="245" y1="256" x2="245" y2="272" class="chain-conn" stroke="#2a3a2a" marker-end="url(#arr)"/>
  <rect x="190" y="274" width="110" height="44" rx="6" class="chain-b-gray"/>
  <text x="245" y="292" text-anchor="middle" dominant-baseline="central" class="chain-h">Send to device</text>
  <text x="245" y="308" text-anchor="middle" dominant-baseline="central" class="chain-s">tx + UTXO + kpub</text>
  <rect x="190" y="322" width="110" height="22" rx="11" class="chain-chip-a"/>
  <text x="245" y="337" text-anchor="middle" dominant-baseline="central" class="chain-t-amber">kpub sent →</text>
  <path d="M300 296 L308 296 L308 382 L312 382" fill="none" stroke="#534AB7" stroke-width="1.5" marker-end="url(#arr)"/>
</g>

<g class="chain-astep" id="st5">
  <rect x="314" y="362" width="160" height="44" rx="6" class="chain-b-purple"/>
  <text x="394" y="380" text-anchor="middle" dominant-baseline="central" class="chain-t-purple">Build sighash</text>
  <text x="394" y="396" text-anchor="middle" dominant-baseline="central" class="chain-s cv-u-6bb91ea0067f">Blake2b(tx + UTXO)</text>
  <rect x="314" y="410" width="160" height="22" rx="11" class="chain-chip-a"/>
  <text x="394" y="425" text-anchor="middle" dominant-baseline="central" class="chain-t-amber">kpub inside device</text>
  <rect x="314" y="436" width="160" height="22" rx="11" class="chain-chip-c"/>
  <text x="394" y="451" text-anchor="middle" dominant-baseline="central" class="chain-t-coral">kpriv idle</text>
</g>

<g class="chain-astep" id="st6">
  <line x1="394" y1="460" x2="394" y2="478" class="chain-conn" stroke="#534AB7" marker-end="url(#arr)"/>
  <rect x="314" y="480" width="160" height="44" rx="6" class="chain-b-purple"/>
  <text x="394" y="498" text-anchor="middle" dominant-baseline="central" class="chain-t-purple">Display to user</text>
  <text x="394" y="514" text-anchor="middle" dominant-baseline="central" class="chain-s cv-u-6bb91ea0067f">amount + recipient</text>
  <text x="394" y="538" text-anchor="middle" dominant-baseline="central" class="chain-t-teal cv-u-33ee29812798">user confirms ✓</text>
</g>

<g class="chain-astep" id="st7">
  <line x1="394" y1="544" x2="394" y2="562" class="chain-conn" stroke="#534AB7" marker-end="url(#arr)"/>
  <rect x="314" y="564" width="160" height="44" rx="6" class="chain-b-purple"/>
  <text x="394" y="582" text-anchor="middle" dominant-baseline="central" class="chain-t-purple">Schnorr sign</text>
  <text x="394" y="598" text-anchor="middle" dominant-baseline="central" class="chain-s cv-u-6bb91ea0067f">Sch(di, kpriv) = sig</text>
  <rect x="314" y="612" width="160" height="22" rx="11" class="chain-chip-c"/>
  <text x="394" y="627" text-anchor="middle" dominant-baseline="central" class="chain-t-coral">kpriv used — stays here</text>
  <rect x="314" y="638" width="160" height="22" rx="11" class="chain-chip-a"/>
  <text x="394" y="653" text-anchor="middle" dominant-baseline="central" class="chain-t-amber">kpub → into output</text>
</g>

<g class="chain-astep" id="st8">
  <path d="M314 586 L306 586 L306 698 L300 698" fill="none" stroke="#2a3a2a" stroke-width="1.5" marker-end="url(#arr)"/>
  <rect x="190" y="676" width="110" height="44" rx="6" class="chain-b-gray"/>
  <text x="245" y="694" text-anchor="middle" dominant-baseline="central" class="chain-h">SignatureScript</text>
  <text x="245" y="710" text-anchor="middle" dominant-baseline="central" class="chain-s">sig + kpub</text>
  <rect x="190" y="724" width="110" height="22" rx="11" class="chain-chip-a"/>
  <text x="245" y="739" text-anchor="middle" dominant-baseline="central" class="chain-t-amber">kpub exits device</text>
  <path d="M300 696 L486 696" fill="none" stroke="#1D9E75" stroke-width="1.5" marker-end="url(#arr)"/>
  <rect x="488" y="676" width="162" height="44" rx="6" class="chain-b-teal"/>
  <text x="569" y="694" text-anchor="middle" dominant-baseline="central" class="chain-h">Confirm tx</text>
  <text x="569" y="710" text-anchor="middle" dominant-baseline="central" class="chain-t-teal cv-u-c28fa1ae60e2">verify sig with kpub</text>
  <rect x="488" y="724" width="162" height="22" rx="11" class="chain-chip-a"/>
  <text x="569" y="739" text-anchor="middle" dominant-baseline="central" class="chain-t-amber">kpub confirms ownership</text>
  <line x1="394" y1="94" x2="394" y2="562" stroke="#1D9E75" stroke-width="0.4" stroke-dasharray="4 4" opacity="0.2"/>
</g>
</svg>

<div id="step-text" class="cv-u-2f3e61836490"></div>

<!-- controls -->
<div class="cv-u-0ab292276143">
  <span id="step-label" class="cv-u-f9d3e60f606f">step 0 of 8</span>
  <div class="cv-u-0d76d82849c1">
    <button id="btn-back" disabled class="cv-u-5a1999cc6d79">← prev</button>
    <button id="btn-next" class="cv-u-ad8c79c8a8f3">next →</button>
  </div>
</div>
</div>`,
    satellites: [
      { id: 'utxo-flow', label: 'UTXO flow', r: 18 },
      { id: 'key-deriv', label: 'Key derivation', r: 18 }
    ]
  };
const actBuild = {
    id: 'build', label: 'Build it',
    x: 0.72, y: 0.72, r: 40,
    num: '04',
    title: 'From source code\nto <em>signing device</em>.',
    body: `
      <p class="act-body cv-u-85f41527d93a">You do not need to be a developer. You need a computer, a USB-C cable, and an <strong>ESP32-S3 board</strong> — either the Waveshare ESP32-S3 Touch LCD 2" or the M5Stack CoreS3. That is the entire bill of materials.</p>
      <p class="act-body cv-u-480775b97f4e">The code lives on GitHub — open, auditable, versioned. Getting it onto your device takes three steps. The first one is optional. But it is the whole point.</p>
      <div class="act-rule cv-u-fd571900bea5"></div>
      <p class="act-body cv-u-0aa541c7d500"><strong>First — verify.</strong> Clone the repository. Inside is a Dockerfile that freezes every component of the build: the exact Ubuntu version, the exact Rust compiler, every dependency pinned in Cargo.lock. Run <strong>docker build</strong> on any machine — macOS, Linux, Windows — and it produces a firmware binary with a SHA-256 hash. Compare that hash to the one published in the release notes. If they match, the binary was built from that source code. Nothing else.</p>
      <p class="act-body cv-u-fa469dbd52df">The firmware embeds its own hash — the device checks it at every boot. That creates a loop: changing the hash changes the binary, which changes the hash. The Docker build solves this by compiling <strong>three times</strong> until the hash stabilizes. This is called <strong>hash convergence</strong>.</p>
      <p class="act-body cv-u-d3f650a25cf0">If you trust the project, skip this step. If you don't — and in this space, you shouldn't — verify first.</p>
      <div class="act-rule cv-u-6428576618bc"></div>
      <p class="act-body cv-u-e753952120c6"><strong>Then — download.</strong> Get the release zip from GitHub. Now you know what is inside it.</p>
      <div class="act-rule cv-u-18bd494c6fe0"></div>
      <p class="act-body cv-u-df4c9f1bb32e"><strong>Then — install.</strong> Plug in your board, erase the flash, write the binary with <strong>esptool</strong> or <strong>espflash</strong>. That works on macOS, Linux, and Windows.</p>
      <p class="act-body cv-u-34c860494659"><strong>On macOS</strong>, the zip includes an installer script. Open Terminal, navigate to the extracted folder, and run:</p>
      <blockquote class="act-quote cv-u-392e4a67a6c5">bash install.sh</blockquote>
      <p class="act-body cv-u-432d3174a094">The script asks permission at every step — just answer <strong>Y</strong> or <strong>N</strong>. It scans your machine for four build tools: <span class="tool-tip">Xcode Command Line Tools<span class="tip-box">Apple's basic build tools — compiler, linker, make. Required on macOS before anything else can compile.</span></span>, <span class="tool-tip">Rust<span class="tip-box">The programming language KasSigner is written in. Bare-metal no_std Rust. No operating system. No garbage collector.</span></span>, the <span class="tool-tip">ESP32 Rust toolchain<span class="tip-box">A modified Rust compiler that produces machine code for the ESP32-S3's Xtensa LX7 cores. Installed via espup — Espressif's toolchain manager. ~1 GB download, 5–15 minutes.</span></span>, and <span class="tool-tip">espflash<span class="tip-box">The flashing tool. Sends the compiled firmware binary to the device over USB. Also used to erase the flash before a clean install.</span></span>. Installs what is missing, then four steps: plug in, erase, build from the source you already verified, flash. You compiled it yourself. You know exactly what is on that chip.</p>
      <div class="act-rule cv-u-9b492c5e4eca"></div>
      <p class="act-body cv-u-6edcd30ba7a9">When the firmware lands on the chip, you unplug the cable. The device boots. The screen lights up. From this moment, it has never touched the internet — and it never will.</p>
      <blockquote class="act-quote cv-u-11989cada284">Don't trust. Verify.<br>Then download. Then install.</blockquote>`,
    satellites: []
  };
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
const actKassee = {
    id: 'kassee', label: 'KasSee',
    x: 0.58, y: 0.50, r: 50,
    num: '06',
    title: 'The eyes that\n<em>never see the key</em>.',
    body: `
      <p class="act-body cv-u-85f41527d93a"><strong>KasSigner</strong> is air-gapped. It cannot talk to the network. Something has to.</p>
      <p class="act-body cv-u-480775b97f4e"><strong>KasSee</strong> is that something. A watch-only companion wallet that runs in your browser — pure Rust compiled to <span class="tool-tip">WebAssembly<span class="tip-box">A binary format that runs inside the browser at near-native speed. The code is compiled from the same Rust source as the device firmware — auditable, reproducible, no JavaScript in the crypto path.</span></span>. No server. No cloud. No accounts. Close the tab and everything is gone — zero persistence.</p>
      <div class="act-rule cv-u-fd571900bea5"></div>
      <p class="act-body cv-u-0aa541c7d500">You give KasSee your <strong>public key</strong> — exported from <strong>KasSigner</strong> as a QR code. From that single key it derives all your addresses, connects to a Kaspa node, and queries the network for your <strong>UTXOs</strong> — the unspent outputs we talked about in the chain. Each one is a sealed envelope with an amount and a lock. KasSee can see them all. It can never open them.</p>
      <p class="act-body cv-u-0dc73b5f729d">When you want to send, KasSee selects the UTXOs needed to cover the amount, builds the unsigned transaction — destination, value, change address — and displays it as an animated QR code. <strong>KasSigner</strong> scans it, shows you the details on its own screen, and signs. The signed transaction comes back via QR. KasSee broadcasts it to the network.</p>
      <div class="act-rule cv-u-1b36ca052773"></div>
      <p class="act-body cv-u-7515b7fc2c3b">KasSee is <strong>not a security boundary</strong>. It runs in an environment you do not control — the browser, the OS, the network, the DNS. A phishing clone can show you one address and put another in the QR. Browser malware can rewrite the transaction in memory.</p>
      <p class="act-body cv-u-58343cf5786a">That said, it is not defenseless either. The WebAssembly binary is compiled from the same open Rust source — you can verify it matches with a Docker reproducible build, just like the firmware. A phishing site would need to serve a different binary, and the hash would not match. That raises the bar. But it does not replace the final check: <strong>verify on the KasSigner screen</strong>. The device shows what is actually in the transaction data. Not what the browser claims.</p>
      <div class="act-rule cv-u-3bae33251edd"></div>
      <p class="act-body cv-u-3ec95397eb29">By default KasSee connects to a public Kaspa node — zero configuration. But the node operator sees your addresses and your IP. For real sovereignty, run your own node and point KasSee at it — a reverse proxy with TLS is enough to make it work from your phone over your local network. Your node, your rules, your view of what you own.</p>
      <blockquote class="act-quote cv-u-7ec00dbcbb3c">KasSee sees everything.<br>KasSee signs nothing.<br>The device is the only authority.</blockquote>`,
    satellites: []
  };
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
const actSovereign = {
    id: 'sovereign', label: 'Sovereignty',
    x: 0.12, y: 0.50, r: 42,
    num: '08',
    title: 'The moment a human\nand mathematics <em>touch</em>.',
    body: `
      <p class="act-body cv-u-85f41527d93a">The user does not need to understand cryptography. They need to see a number on a screen they trust, and confirm it.</p>
      <div class="act-rule cv-u-480775b97f4e"></div>
      <p class="act-body cv-u-faa4089b0f47">That confirmation — on the <strong>KasSigner</strong> display — is not a UX interaction. The screen is not connected to the internet. The device cannot be instructed remotely. The only way to move those funds is for a human to physically confirm, on that display, that the amount and recipient are correct.</p>
      <p class="act-body cv-u-257594085266">The amount is bound into the signature cryptographically. If the laptop lies about it, the network rejects the transaction. The display and the signature are the same number.</p>
      <div class="act-rule cv-u-2df3c813a2bc"></div>
      <p class="act-body cv-u-1b36ca052773">On March 30, 2026, the first air-gapped hardware-signed Kaspa transaction was broadcast on mainnet using <strong>KasSigner</strong>. A human looked at a screen, confirmed an amount, and pressed a button. The device signed. KasSee broadcast. The network confirmed. That was the moment sovereignty became real — not a whitepaper, not a promise. A transaction.</p>
      <blockquote class="act-quote cv-u-84f667de0142">Not your keys, not your coins.<br>Not your signer, not your node.<br>March 30, 2026 — first ever TX signed with KasSigner.</blockquote>`,
    satellites: []
  };
const actStego = {
    id: 'stego', label: 'The vault',
    x: 0.15, y: 0.25, r: 40,
    num: '09',
    title: 'Your seed hides\nin <em>plain sight</em>.',
    body: `
      <p class="act-body cv-u-85f41527d93a">Every other seed backup method has the same problem: it looks like a seed backup.</p>
      <p class="act-body cv-u-480775b97f4e">A metal plate stamped with 24 words. A paper wallet in a safe. An encrypted file named seed_backup.enc. Any attacker who finds these knows exactly what they have.</p>
      <p class="act-body cv-u-428f1ba92009">A photo of your dog is not a seed backup. It is a photo of your dog.</p>
      <div class="act-rule cv-u-823b59ecd3d2"></div>
      <p class="act-body cv-u-0dc73b5f729d"><strong>KasSigner</strong> embeds your encrypted seed inside a JPEG photograph using <span class="tool-tip">EXIF metadata<span class="tip-box">The standard metadata format every digital camera writes — date, GPS, camera model, exposure, and text fields like ImageDescription. Use thousands of copies across safe channels. Some platforms strip EXIF — always test your backup channel.</span></span>. The image is mathematically identical — every pixel untouched. The file size change is below the noise floor of JPEG compression.</p>
      <p class="act-body cv-u-68b708ffe84d">The caption you wrote on the photo — <em>"Rocky at the beach, summer 2024"</em> — is the encryption key. Not a hint toward the key. It <em>is</em> the key, fed through PBKDF2 to derive AES-256-GCM. Anyone can read the caption. Nobody knows it matters.</p>
      <div class="act-rule cv-u-6428576618bc"></div>
      <p class="act-body cv-u-e753952120c6">You can scatter copies across channels that preserve EXIF — file copies, USB sticks, Google Drive, Dropbox, email attachments. Thousands of photos. Nobody knows which one matters. But be careful — social media strips metadata. Twitter, Instagram, WhatsApp will destroy the backup. Always test your channel: upload a photo, download it back, check the EXIF survived.</p>
      <p class="act-body cv-u-df4c9f1bb32e">And even if someone finds the right file, decrypts it, recovers all 24 words — the real wallet lives behind the BIP39 passphrase, the 25th word that exists only in your memory. A recovery hint can be embedded alongside the seed — a question whose answer is your 25th word. Years from now, when memory fades, the hint is there. But only for someone who already proved they know the caption.</p>
      <blockquote class="act-quote cv-u-2c16998ff44c">The needle looks exactly like hay.<br>And even if someone finds it —<br>it is still encrypted.</blockquote>`,
    satellites: []
  };
const acts = [
  actEthos,
  actMultisig,
  actChain,
  actBuild,
  actDevice,
  actKassee,
  actSecurity,
  actSovereign,
  actStego,
];
// UTXO-flow satellite markup. Kept separate from navigation lifecycle.

const utxoFlowMarkup = `<div id="anim-wrap" class="cv-u-1e6fdc20e118">

<svg id="anim-svg" width="100%" viewBox="0 0 680 540" xmlns="http://www.w3.org/2000/svg" class="cv-u-604449e974fd">
<defs>
  <marker id="uarr" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
    <path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
  </marker>

</defs>

<!-- Step 0: Title — always visible -->
<g class="utxo-ut utxo-on" id="ut0">
  <text x="340" y="28" text-anchor="middle" class="utxo-h cv-u-ca11385bb59c">Multi-input Kaspa transaction</text>
  <text x="340" y="48" text-anchor="middle" class="utxo-s">Each input is a UTXO from a different address, each needs its own key</text>
</g>

<!-- Step 1: Three UTXO inputs appear -->
<g class="utxo-ut" id="ut1">
  <text x="105" y="82" text-anchor="middle" class="utxo-h cv-u-e4784d0598c0">UTXOs (inputs)</text>

  <rect x="20" y="96" width="170" height="50" rx="8" class="utxo-b-blue"/>
  <text x="105" y="115" text-anchor="middle" class="utxo-t-blue cv-u-a49cca52becd">Receive #0</text>
  <text x="105" y="133" text-anchor="middle" class="utxo-s">0.5 KAS · m/.../0/0</text>

  <rect x="20" y="158" width="170" height="50" rx="8" class="utxo-b-teal"/>
  <text x="105" y="177" text-anchor="middle" class="utxo-t-teal cv-u-a49cca52becd">Receive #2</text>
  <text x="105" y="195" text-anchor="middle" class="utxo-s">0.5 KAS · m/.../0/2</text>

  <rect x="20" y="220" width="170" height="50" rx="8" class="utxo-b-amber"/>
  <text x="105" y="239" text-anchor="middle" class="utxo-t-amber cv-u-a49cca52becd">Change #1</text>
  <text x="105" y="257" text-anchor="middle" class="utxo-s">2.0 KAS · m/.../1/1</text>
</g>

<!-- Step 2: Transaction box -->
<g class="utxo-ut" id="ut2">
  <path d="M190 121 L250 181" fill="none" stroke="#378ADD" stroke-width="1" opacity="0.5" marker-end="url(#uarr)"/>
  <path d="M190 183 L250 183" fill="none" stroke="#1D9E75" stroke-width="1" opacity="0.5" marker-end="url(#uarr)"/>
  <path d="M190 245 L250 195" fill="none" stroke="#BA7517" stroke-width="1" opacity="0.5" marker-end="url(#uarr)"/>

  <rect x="254" y="126" width="172" height="116" rx="8" class="utxo-b-gray"/>
  <text x="340" y="150" text-anchor="middle" class="utxo-h">Transaction</text>
  <text x="340" y="170" text-anchor="middle" class="utxo-s">3 inputs → 2 outputs</text>
  <rect x="270" y="182" width="140" height="22" rx="11" class="utxo-chip-t"/>
  <text x="340" y="197" text-anchor="middle" class="utxo-t-teal">Total in: 3.0 KAS</text>
  <rect x="270" y="210" width="140" height="22" rx="11" class="utxo-chip-c"/>
  <text x="340" y="225" text-anchor="middle" class="utxo-t-coral">Fee: 0.0001 KAS</text>
</g>

<!-- Step 3: Outputs -->
<g class="utxo-ut" id="ut3">
  <path d="M426 160 L490 130" fill="none" stroke="#F0997B" stroke-width="1" opacity="0.5" marker-end="url(#uarr)"/>
  <path d="M426 200 L490 218" fill="none" stroke="#BA7517" stroke-width="1" opacity="0.5" marker-end="url(#uarr)"/>

  <text x="575" y="82" text-anchor="middle" class="utxo-h cv-u-e4784d0598c0">Outputs</text>

  <rect x="494" y="96" width="170" height="50" rx="8" class="utxo-b-purple"/>
  <text x="579" y="115" text-anchor="middle" class="utxo-t-purple cv-u-a49cca52becd">Destination</text>
  <text x="579" y="133" text-anchor="middle" class="utxo-s cv-u-6bb91ea0067f">1.5 KAS</text>

  <rect x="494" y="200" width="170" height="50" rx="8" class="utxo-b-amber"/>
  <text x="579" y="219" text-anchor="middle" class="utxo-t-amber cv-u-a49cca52becd">Change #2</text>
  <text x="579" y="237" text-anchor="middle" class="utxo-s">1.4999 KAS · m/.../1/2</text>
</g>

<!-- Step 4: Signing per input — headers -->
<g class="utxo-ut" id="ut4">
  <line x1="20" y1="296" x2="660" y2="296" stroke="#2a3a2a" stroke-width="0.5" stroke-dasharray="4 4"/>
  <text x="340" y="320" text-anchor="middle" class="utxo-h cv-u-43c8fad341a3">Signing — per input</text>
</g>

<!-- Step 5: Three signing boxes appear one by one -->
<g class="utxo-ut" id="ut5">
  <rect x="20" y="338" width="200" height="64" rx="8" class="utxo-b-blue"/>
  <text x="120" y="358" text-anchor="middle" class="utxo-t-blue cv-u-a49cca52becd">Input #0 signing</text>
  <text x="120" y="378" text-anchor="middle" class="utxo-s">Key from m/.../0/0</text>
  <rect x="20" y="406" width="200" height="22" rx="11" class="utxo-chip-a"/>
  <text x="120" y="421" text-anchor="middle" class="utxo-t-amber">Schnorr sig → 64 bytes</text>

  <rect x="240" y="338" width="200" height="64" rx="8" class="utxo-b-teal"/>
  <text x="340" y="358" text-anchor="middle" class="utxo-t-teal cv-u-a49cca52becd">Input #1 signing</text>
  <text x="340" y="378" text-anchor="middle" class="utxo-s">Key from m/.../0/2</text>
  <rect x="240" y="406" width="200" height="22" rx="11" class="utxo-chip-a"/>
  <text x="340" y="421" text-anchor="middle" class="utxo-t-amber">Schnorr sig → 64 bytes</text>

  <rect x="460" y="338" width="200" height="64" rx="8" class="utxo-b-amber"/>
  <text x="560" y="358" text-anchor="middle" class="utxo-t-amber cv-u-a49cca52becd">Input #2 signing</text>
  <text x="560" y="378" text-anchor="middle" class="utxo-s">Key from m/.../1/1</text>
  <rect x="460" y="406" width="200" height="22" rx="11" class="utxo-chip-a"/>
  <text x="560" y="421" text-anchor="middle" class="utxo-t-amber">Schnorr sig → 64 bytes</text>
</g>

<!-- Step 6: Summary note -->
<g class="utxo-ut" id="ut6">
  <rect x="60" y="446" width="560" height="80" rx="8" fill="#0f1410" stroke="#1a2418" stroke-width="0.6"/>
  <text x="340" y="468" text-anchor="middle" class="utxo-s cv-u-dbcf63841f1b">For each input, KasSigner finds the pubkey in the script,</text>
  <text x="340" y="484" text-anchor="middle" class="utxo-s cv-u-dbcf63841f1b">searches receive chain (m/.../0/x) then change chain (m/.../1/x),</text>
  <text x="340" y="500" text-anchor="middle" class="utxo-s cv-u-dbcf63841f1b">derives the private key, computes sighash, signs with Schnorr.</text>
  <text x="340" y="520" text-anchor="middle" class="utxo-s cv-u-759a12861428">The fee is implicit: sum(inputs) − sum(outputs) = fee. No fee output.</text>
</g>

</svg>

<div id="step-text" class="cv-u-2f3e61836490"></div>

<!-- controls -->
<div class="cv-u-0ab292276143">
  <span id="step-label" class="cv-u-f9d3e60f606f">step 0 of 6</span>
  <div class="cv-u-0d76d82849c1">
    <button id="btn-back" disabled class="cv-u-5a1999cc6d79">← prev</button>
    <button id="btn-next" class="cv-u-ad8c79c8a8f3">next →</button>
  </div>
</div>
</div>`;
// Key-derivation satellite content and local navigation controller.

const derivationFlowMarkup = `<div id="deriv-root"><div class="viewport cv-u-2a9495ecbb8f">
  <div class="top-bar">
    <div class="step-counter" id="dv-counter">Step 1 of 10</div>
    <div class="step-heading" id="dv-heading"></div>
    <div class="step-desc" id="dv-desc"></div>
  </div>

  <div class="progress-track"><div class="progress-fill" id="dv-progress"></div></div>

  <div class="diagram-scroll" id="dv-scroll-area">
    <div class="diagram-inner" id="dv-diagram"><div class="cv-u-bea203147472"></div><div class="row" data-row="0">
    <div class="box box-amber cv-u-43459be14cf5"><div class="box-title">Your 12 / 24 words</div><div class="box-label">The secret you write down</div></div>
    <div class="cv-u-04459059885b"></div>
    <div class="box box-coral cv-u-15b59c1a9af1"><div class="box-title">Passphrase</div><div class="box-label">Optional extra word</div></div>
  </div>
  <div class="arrow-down" data-row="1">↓</div>
  <div class="row" data-row="1">
    <div class="box box-gray cv-u-044e5ee61236"><div class="box-title">Slow mixing — 2048 rounds</div><div class="box-label">PBKDF2: Password-Based Key Derivation Function</div></div>
  </div>
  <div class="arrow-down" data-row="2">↓</div>
  <div class="row" data-row="2">
    <div class="box box-amber cv-u-45435946eaf3"><div class="box-title">Seed — your master secret</div></div>
  </div>
  <div class="arrow-down" data-row="3">↓</div>
  <div class="row" data-row="3">
    <div class="box box-gray cv-u-044e5ee61236"><div class="box-title">One-way blender</div><div class="box-label">HMAC: Hash-based Message Authentication Code</div></div>
  </div>
  <div class="split-label" data-row="4">split in half</div>
  <div class="row" data-row="4">
    <div class="side-label dimmed">xprv</div>
    <div class="box box-teal"><div class="box-title">m — Private key</div><div class="box-label">left 256 bits</div></div>
    <div class="box box-purple"><div class="box-title">Chain code</div><div class="box-label">right 256 bits</div></div>
    <div class="side-label dimmed">xpub</div>
  </div>
  <div class="arrow-down" data-row="5">↓</div>
  <div class="row" data-row="5">
    <div class="side-label dimmed">xprv</div>
    <div class="blender-row"><div class="box box-gray cv-u-0eddd0ab78c0"><div class="box-title">Blender (HMAC-SHA512)</div></div><span class="chip chip-amber">index: 44</span></div>
    <div class="side-label dimmed">xpub</div>
  </div>
  <div class="arrow-down" data-row="6">↓</div>
  <div class="row" data-row="6">
    <div class="side-label dimmed">xprv</div>
    <div class="box box-teal cv-u-4aa3ae593446"><div class="box-title">44' key</div></div>
    <div class="box box-purple cv-u-4aa3ae593446"><div class="box-title">44' chain code</div></div>
    <div class="side-label dimmed">xpub</div>
  </div>
  <div class="arrow-down" data-row="7">↓</div>
  <div class="row" data-row="7">
    <div class="blender-row"><div class="box box-gray cv-u-0eddd0ab78c0"><div class="box-title">Blender (HMAC-SHA512)</div></div><span class="chip chip-amber">index: 111111</span></div>
  </div>
  <div class="arrow-down" data-row="8">↓</div>
  <div class="row" data-row="8">
    <div class="side-label bright">xprv</div>
    <div class="box box-teal"><div class="box-title">0' private key</div><div class="box-label">account level</div></div>
    <div class="box box-purple"><div class="box-title">0' chain code</div><div class="box-label">account level</div></div>
    <div class="side-label bright">xpub</div>
  </div>
  <div class="arrow-down" data-row="9">↓</div>
  <div class="row" data-row="9">
    <div class="blender-row cv-u-e54a17aea6cd">
      <div class="box box-gray cv-u-0eddd0ab78c0"><div class="box-title">Blender x2 (HMAC-SHA512)</div></div>
      <div class="cv-u-2a7b63546e65"><span class="chip chip-amber">index: 0, 0</span><span class="chip chip-gray">0/1 = receive/change</span><span class="chip chip-gray">0,1,2… = addresses</span></div>
    </div>
  </div>
  <div class="arrow-down" data-row="10">↓</div>
  <div class="row" data-row="10">
    <div class="box box-teal"><div class="box-title">Final private key</div><div class="box-label">Signs transactions</div></div>
    <div class="cv-u-5e66a8d92d70">curve →</div>
    <div class="box box-blue"><div class="box-title">Public key (kpub)</div><div class="box-label">Verifies signatures</div></div>
  </div>
  <div class="arrow-down" data-row="11">↓</div>
  <div class="row" data-row="11">
    <div class="box box-gray cv-u-0b5f5d0c430f"><div class="box-title">Hash the public key</div><div class="box-label">shorter, safer to share</div></div>
  </div>
  <div class="arrow-down" data-row="12">↓</div>
  <div class="row" data-row="12">
    <div class="box box-pink cv-u-044e5ee61236"><div class="box-title cv-u-33ee29812798">kaspa:qr...your address...xyz</div><div class="box-label">This is what you share — m/44'/111111'/0'/0/0</div></div>
  </div>
  <div class="cv-u-7ec4898503f7"></div>
  <div class="row cv-u-0b9369172dcd" data-row="13">
    <div class="signing-zone">
      <div class="zone-label">When you spend</div>
      <div class="signing-inner">
        <div class="signing-panel kassee" data-row="14">
          <div class="panel-title">KasSee</div>
          <div class="panel-item">(web wallet)</div>
          <div class="panel-item hl cv-u-eb2cdaa55e9f">Fetches UTXOs</div>
          <div class="panel-item hl">Builds sighash</div>
          <div class="panel-item">(UTXO+kpub+out)</div>
        </div>
        <div class="qr-col"><span class="qr-label">QR →</span></div>
        <div class="signing-panel kassigner" data-row="15">
          <div class="panel-title">KasSigner</div>
          <div class="panel-item">(air-gapped)</div>
          <div class="panel-item hl cv-u-eb2cdaa55e9f">Private key</div>
          <div class="panel-item hl">+ sighash</div>
          <div class="panel-item hl cv-u-04e6ec98c0cf">→ Schnorr sig</div>
        </div>
        <div class="qr-col"><span class="qr-label">QR →</span></div>
        <div class="signing-panel kassee" data-row="16">
          <div class="panel-title">KasSee</div>
          <div class="panel-item hl cv-u-eb2cdaa55e9f">Broadcasts</div>
          <div class="panel-item hl">to network</div>
        </div>
      </div>
      <div data-row="17">
        <div class="verify-box"><div class="box-title">Network verifies: Schnorr sig + kpub + sighash</div><div class="box-label">Valid? Accepted. Invalid? Rejected.</div></div>
      </div>
    </div>
  </div>
  <div class="cv-u-7217a7abdd34"></div></div>
  </div>

  <div class="summary-bar">
    <p><span class="b">xprv</span> = eXtended PRiVate key (key + chain code). <span class="b">xpub</span> = eXtended PUBlic key (view only).</p>
    <p><span class="b">KasSee</span> builds + broadcasts. <span class="b">KasSigner</span> signs. Private key never crosses the air gap.</p>
  </div>
<div class="cv-u-bb6f274002cf">
  <span id="dv-step-label" class="cv-u-64891d88238d">step 1 of 10</span>
  <div class="cv-u-0d76d82849c1">
    <button id="dv-btn-back" disabled class="cv-u-466b09450a31">← prev</button>
    <button id="dv-btn-next" class="cv-u-58ffe46bf6fc">next →</button>
  </div>
</div>
</div>

<div class="scroll-hint" id="dv-hint">click diagram to advance ↕</div></div>`;

const derivationFlowSteps = [
  { heading: "Your 12 or 24 words + passphrase", desc: "Everything starts here. Your mnemonic is the human-readable form of entropy. The optional passphrase acts as a \"25th word\" \u2014 different passphrase, completely different wallet.", active: [0] },
  { heading: "Slow mixing \u2014 PBKDF2", desc: "Words and passphrase get hashed 2048 times through PBKDF2 (Password-Based Key Derivation Function). Deliberate slowness makes brute-force expensive \u2014 ~4096 SHA-512 ops per guess.", active: [1] },
  { heading: "Seed \u2192 master key + chain code", desc: "The 512-bit seed goes through HMAC (Hash-based Message Authentication Code) and splits in half: left = master private key, right = chain code \u2014 extra randomness that makes each branch unique.", active: [2, 3, 4] },
  { heading: "Derivation tree \u2014 blender passes", desc: "At each level: private key + chain code + index number go into the HMAC-SHA512 blender. Out comes a new key and chain code. The indices (44, 111111, 0) form the path m/44h/111111h/0h.", active: [5, 6, 7] },
  { heading: "Account level \u2014 xprv and xpub", desc: "At account level (0h), the extended keys become important. xprv here controls all Kaspa keys below. xpub can derive all addresses without the secret \u2014 watch-only wallets.", active: [8] },
  { heading: "Receive chain + address index", desc: "Two more blender passes: first picks receive (0) vs change (1) chain, second picks address index (0, 1, 2\u2026). This produces the final private key for one specific address.", active: [9] },
  { heading: "Private key \u2192 public key \u2192 address", desc: "Final private key \u00d7 elliptic curve = public key (kpub). Hash the kpub = Kaspa address. Private key signs. Public key verifies. Address is what goes on-chain.", active: [10, 11, 12] },
  { heading: "KasSee builds the sighash", desc: "KasSee (web wallet) fetches UTXOs from the network, combines them with kpub and outputs, and hashes everything into a sighash \u2014 the digest that will be signed.", active: [13, 14] },
  { heading: "KasSigner signs \u2014 air-gapped", desc: "Sighash travels to KasSigner via QR. The device combines it with the private key (which never left) and produces a Schnorr signature. Signature returns via QR. Secret never crosses the air gap.", active: [13, 15] },
  { heading: "Broadcast + network verification", desc: "KasSee broadcasts the signed transaction. Every node verifies: does the Schnorr signature match the kpub and sighash? Valid = accepted. Invalid = rejected. The kpub is revealed on-chain only now.", active: [13, 16, 17] }
];

function mountDerivationFlow(root) {
  if (!root) return null;

  let current = 0;
  let locked = false;

  function goTo(index) {
    if (index < 0 || index >= derivationFlowSteps.length || locked) return;
    locked = true;
    current = index;
    const step = derivationFlowSteps[index];

    root.querySelector('#dv-counter').textContent = `Step ${index + 1} of ${derivationFlowSteps.length}`;
    root.querySelector('#dv-heading').textContent = step.heading;
    root.querySelector('#dv-desc').textContent = step.desc;
    root.querySelector('#dv-progress').style.width = `${(index + 1) / derivationFlowSteps.length * 100}%`;

    const activeRows = new Set(step.active);
    const visitedRows = new Set(derivationFlowSteps.slice(0, index).flatMap(previous => previous.active));
    root.querySelectorAll('[data-row]').forEach(element => {
      const row = Number.parseInt(element.dataset.row, 10);
      element.classList.remove('active', 'visited', 'upcoming');
      if (activeRows.has(row)) element.classList.add('active');
      else if (visitedRows.has(row)) element.classList.add('visited');
      else element.classList.add('upcoming');
    });

    root.querySelectorAll('.arrow-down, .split-label').forEach(element => {
      const row = Number.parseInt(element.dataset.row, 10);
      element.classList.remove('active', 'visited');
      if (activeRows.has(row)) element.classList.add('active');
      else if (visitedRows.has(row)) element.classList.add('visited');
    });

    const firstRow = root.querySelector(`[data-row="${step.active[0]}"].row`)
      || root.querySelector(`[data-row="${step.active[0]}"].signing-zone`);
    if (firstRow) {
      const container = root.querySelector('#dv-scroll-area');
      const diagram = root.querySelector('#dv-diagram');
      const target = firstRow.offsetTop - container.clientHeight / 2 + firstRow.offsetHeight / 2;
      diagram.style.transform = `translateY(${-Math.max(0, target)}px)`;
    }

    root.querySelector('#dv-hint')?.classList.add('hidden');
    const backButton = root.querySelector('#dv-btn-back');
    const nextButton = root.querySelector('#dv-btn-next');
    const label = root.querySelector('#dv-step-label');
    if (label) label.textContent = `step ${index + 1} of ${derivationFlowSteps.length}`;
    if (backButton) {
      backButton.disabled = index === 0;
      backButton.style.opacity = index === 0 ? '0.3' : '1';
    }
    if (nextButton) {
      nextButton.disabled = index === derivationFlowSteps.length - 1;
      nextButton.style.opacity = nextButton.disabled ? '0.3' : '1';
      nextButton.textContent = nextButton.disabled ? 'done ✓' : 'next →';
    }

    setTimeout(() => { locked = false; }, 400);
  }

  const next = () => goTo(current + 1);
  const previous = () => goTo(current - 1);
  root.querySelector('#dv-scroll-area')?.addEventListener('click', event => { event.stopPropagation(); next(); });
  root.querySelector('#dv-btn-next')?.addEventListener('click', event => { event.stopPropagation(); next(); });
  root.querySelector('#dv-btn-back')?.addEventListener('click', event => { event.stopPropagation(); previous(); });
  goTo(0);
  return { next, previous };
}
const connections = [
  ['ethos','chain'],['ethos','multisig'],['ethos','sovereign'],['ethos','stego'],
  ['chain','build'],['build','device'],
  ['device','kassee'],['kassee','security'],
  ['security','sovereign'],['security','stego'],
  ['multisig','device'],['multisig','kassee'],
];

// ── ghost shapes ─────────────────────────────────────────
function makeGhosts(W, H) {
  const ghosts = [];
  const count = 18;
  for (let i = 0; i < count; i++) {
    const type = ['circle','ring','arc','poly'][Math.floor(Math.random()*4)];
    ghosts.push({
      type,
      x: Math.random() * W,
      y: Math.random() * H,
      r: 8 + Math.random() * 55,
      speed: (0.04 + Math.random() * 0.12) * (Math.random() > 0.5 ? 1 : -1),
      angle: Math.random() * Math.PI * 2,
      orbitR: 60 + Math.random() * 200,
      cx: Math.random() * W,
      cy: Math.random() * H,
      sides: 3 + Math.floor(Math.random() * 4),
      opacity: 0.015 + Math.random() * 0.04,
      phase: Math.random() * Math.PI * 2,
    });
  }
  return ghosts;
}

// ── star particles ──────────────────────────────────────
function makeStars(W, H) {
  const stars = [];
  for (let i = 0; i < 120; i++) {
    stars.push({
      x: Math.random() * W,
      y: Math.random() * H,
      r: 0.3 + Math.random() * 1.5,
      speed: 0.05 + Math.random() * 0.2,
      drift: (Math.random() - 0.5) * 0.3,
      phase: Math.random() * Math.PI * 2,
      bright: 0.15 + Math.random() * 0.5,
    });
  }
  return stars;
}

// ── node color scheme ───────────────────────────────────
const nodeColors = {
  ethos:     { base: '#2a6b4a', glow: '#1D9E75', accent: '#c8a846', ring: 'rgba(200,168,70,0.12)',
               sphere: ['#243e24','#18291a','#0e180e','#080c06'], spec: 'rgba(200,168,70,0.14)', rim: 'rgba(200,168,70,0.10)' },
  multisig:  { base: '#2a6b4a', glow: '#1D9E75', accent: '#d4a843', ring: 'rgba(212,168,67,0.1)',
               sphere: ['#303624','#222818','#161a0e','#0c0e06'], spec: 'rgba(212,168,67,0.12)', rim: 'rgba(212,168,67,0.08)' },
  chain:     { base: '#1a5040', glow: '#1D9E75', accent: '#1D9E75', ring: 'rgba(29,158,117,0.08)',
               sphere: ['#183e30','#0e2418','#081410','#040c08'], spec: 'rgba(29,158,117,0.10)', rim: 'rgba(29,158,117,0.06)' },
  build:     { base: '#1a5040', glow: '#1D9E75', accent: '#1D9E75', ring: 'rgba(29,158,117,0.08)',
               sphere: ['#183e30','#0e2418','#081410','#040c08'], spec: 'rgba(29,158,117,0.10)', rim: 'rgba(29,158,117,0.06)' },
  device:    { base: '#1D9E75', glow: '#3ffcb0', accent: '#3ffcb0', ring: 'rgba(63,252,176,0.15)',
               sphere: ['#18443a','#104430','#0a3024','#061a14'], spec: 'rgba(63,252,176,0.22)', rim: 'rgba(63,252,176,0.14)' },
  kassee:    { base: '#1D9E75', glow: '#3ffcb0', accent: '#3ffcb0', ring: 'rgba(63,252,176,0.15)',
               sphere: ['#183c44','#0e3038','#082428','#04161c'], spec: 'rgba(80,210,255,0.18)', rim: 'rgba(80,210,255,0.10)' },
  security:  { base: '#993C1D', glow: '#F0997B', accent: '#F0997B', ring: 'rgba(240,153,123,0.08)',
               sphere: ['#302018','#241610','#180e0a','#0e0806'], spec: 'rgba(240,153,123,0.12)', rim: 'rgba(240,153,123,0.08)' },
  sovereign: { base: '#6b5a2a', glow: '#d4a843', accent: '#d4a843', ring: 'rgba(212,168,67,0.12)',
               sphere: ['#302c18','#242010','#181408','#0e0c06'], spec: 'rgba(212,168,67,0.16)', rim: 'rgba(212,168,67,0.10)' },
  stego:     { base: '#4a2a6b', glow: '#b080e0', accent: '#b080e0', ring: 'rgba(176,128,224,0.10)',
               sphere: ['#241830','#1a1224','#120c18','#0a060c'], spec: 'rgba(176,128,224,0.14)', rim: 'rgba(176,128,224,0.08)' },
};

// ── satellite orbit state ────────────────────────────────
function drawGhost(ghost, time) {
  ctx.save();
  ctx.globalAlpha = ghost.opacity * (0.7 + 0.3 * Math.sin(time * 0.4 + ghost.phase));
  ctx.strokeStyle = '#1D9E75';
  ctx.lineWidth = 0.4;
  ctx.fillStyle = 'none';

  const x = ghost.cx + Math.cos(ghost.angle + time * ghost.speed * 0.3) * ghost.orbitR;
  const y = ghost.cy + Math.sin(ghost.angle + time * ghost.speed * 0.3) * ghost.orbitR;
  ctx.beginPath();
  if (ghost.type === 'circle') {
    ctx.arc(x, y, ghost.r, 0, Math.PI * 2);
  } else if (ghost.type === 'ring') {
    ctx.arc(x, y, ghost.r, 0, Math.PI * 2);
    ctx.stroke();
    ctx.beginPath();
    ctx.arc(x, y, ghost.r * 0.6, 0, Math.PI * 2);
  } else if (ghost.type === 'arc') {
    const start = time * ghost.speed + ghost.phase;
    ctx.arc(x, y, ghost.r, start, start + Math.PI * (0.6 + 0.4 * Math.sin(time * 0.2)));
  } else if (ghost.type === 'poly') {
    ctx.moveTo(x + ghost.r * Math.cos(time * ghost.speed * 0.5), y + ghost.r * Math.sin(time * ghost.speed * 0.5));
    for (let index = 1; index <= ghost.sides; index += 1) {
      const angle = (index / ghost.sides) * Math.PI * 2 + time * ghost.speed * 0.5;
      ctx.lineTo(x + ghost.r * Math.cos(angle), y + ghost.r * Math.sin(angle));
    }
    ctx.closePath();
  }
  ctx.stroke();
  ctx.restore();
}

function drawStars(time) {
  stars.forEach(star => {
    star.y -= star.speed;
    star.x += star.drift;
    if (star.y < -5) { star.y = H + 5; star.x = Math.random() * W; }
    if (star.x < -5) star.x = W + 5;
    if (star.x > W + 5) star.x = -5;
    const flicker = star.bright * (0.6 + 0.4 * Math.sin(time * 2.5 + star.phase));
    ctx.beginPath();
    ctx.arc(star.x, star.y, star.r, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(200, 220, 190, ${flicker})`;
    ctx.fill();
  });
}

function drawConnections(time) {
  connections.forEach(([fromId, toId], index) => {
    const fromNode = acts.find(node => node.id === fromId);
    const toNode = acts.find(node => node.id === toId);
    const from = nodePos(fromNode);
    const to = nodePos(toNode);
    const highlighted = [fromNode, toNode].includes(hoveredNode) || [fromNode, toNode].includes(activeNode);

    ctx.beginPath();
    ctx.moveTo(from.x, from.y);
    ctx.lineTo(to.x, to.y);
    ctx.strokeStyle = highlighted ? 'rgba(29,158,117,0.25)' : 'rgba(29,60,40,0.35)';
    ctx.lineWidth = highlighted ? 1 : 0.5;
    ctx.stroke();

    const position = (time * (0.15 + index * 0.02) + index * 0.37) % 1;
    drawConnectionParticle(
      from.x + (to.x - from.x) * position,
      from.y + (to.y - from.y) * position,
      highlighted,
    );
  });
}

function drawConnectionParticle(x, y, highlighted) {
  if (!Number.isFinite(x) || !Number.isFinite(y)) return;
  const size = highlighted ? 3 : 1.5;
  const alpha = highlighted ? 0.6 : 0.2;
  const gradient = ctx.createRadialGradient(x, y, 0, x, y, size * 4);
  gradient.addColorStop(0, `rgba(29,158,117,${alpha})`);
  gradient.addColorStop(1, 'rgba(29,158,117,0)');
  ctx.beginPath();
  ctx.arc(x, y, size * 4, 0, Math.PI * 2);
  ctx.fillStyle = gradient;
  ctx.fill();
  ctx.beginPath();
  ctx.arc(x, y, size, 0, Math.PI * 2);
  ctx.fillStyle = `rgba(63,252,176,${alpha})`;
  ctx.fill();
}
function drawSatellites(node, x, y, time) {
  if (node !== hoveredNode || !node.satellites?.length || satProgress <= 0.02) return;
  node.satellites.forEach((satellite, index) => {
    const position = satPos(node, index, node.satellites.length, satProgress);
    const hovered = isSatHovered(node, index);
    const radius = satellite.r * satProgress;
    const pulse = Math.sin(time * 1.5 + index * 2.0) * 0.5 + 0.5;
    drawSatelliteConnector(x, y, position);
    drawSatelliteGlow(position, radius, pulse, hovered);
    drawSatelliteBody(position, radius, hovered);
    drawSatelliteLabel(satellite, position, radius, hovered);
  });
}

function drawSatelliteConnector(x, y, position) {
  ctx.beginPath();
  ctx.moveTo(x, y);
  ctx.lineTo(position.x, position.y);
  ctx.strokeStyle = `rgba(29,158,117,${0.3 * satProgress})`;
  ctx.lineWidth = 0.8;
  ctx.setLineDash([4, 4]);
  ctx.stroke();
  ctx.setLineDash([]);
}

function drawSatelliteGlow(position, radius, pulse, hovered) {
  if (satProgress > 0.3) {
    const glowRadius = radius + 10 + pulse * 4;
    const gradient = ctx.createRadialGradient(position.x, position.y, radius * 0.5, position.x, position.y, glowRadius);
    gradient.addColorStop(0, hovered ? 'rgba(29,158,117,0.25)' : 'rgba(29,158,117,0.12)');
    gradient.addColorStop(1, 'rgba(29,158,117,0)');
    ctx.beginPath();
    ctx.arc(position.x, position.y, glowRadius, 0, Math.PI * 2);
    ctx.fillStyle = gradient;
    ctx.globalAlpha = satProgress;
    ctx.fill();
    ctx.globalAlpha = 1;
  }
  if (satProgress > 0.4) {
    ctx.beginPath();
    ctx.arc(position.x, position.y, radius + 4 + pulse * 3, 0, Math.PI * 2);
    ctx.strokeStyle = `rgba(29,158,117,${(hovered ? 0.5 : 0.25) * satProgress})`;
    ctx.lineWidth = 0.6;
    ctx.stroke();
  }
}

function drawSatelliteBody(position, radius, hovered) {
  ctx.beginPath();
  ctx.arc(position.x, position.y, radius, 0, Math.PI * 2);
  ctx.fillStyle = hovered ? '#0f3828' : '#0a2418';
  ctx.fill();
  ctx.strokeStyle = hovered ? '#3ffcb0' : '#1D9E75';
  ctx.lineWidth = hovered ? 1.2 : 0.8;
  ctx.stroke();
}

function drawSatelliteLabel(satellite, position, radius, hovered) {
  if (satProgress <= 0.3) return;
  ctx.font = `400 ${Math.round(11 * satProgress)}px "IBM Plex Mono"`;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillStyle = hovered ? '#e0f4ec' : '#9fcfbc';
  ctx.globalAlpha = Math.min(1, (satProgress - 0.3) * 1.5);
  ctx.fillText(satellite.label, position.x, position.y + radius + 14);
  ctx.globalAlpha = 1;
}
function drawNode(node, index, time) {
  const { x, y } = nodePos(node);
  const hovered = node === hoveredNode || node === activeNode;
  const colors = nodeColors[node.id] || nodeColors.chain;
  const pulse = Math.sin(time * 0.7 + index * 1.05) * 2;
  const breathe = Math.sin(time * 0.3 + index * 0.8) * 0.5 + 0.5;
  const radius = node.r + (hovered ? 6 : 0);
  drawNodeGlow(x, y, radius, pulse, breathe, hovered, colors);
  drawNodeSphere(x, y, radius, pulse, breathe, hovered, colors);
  drawNodeLabel(node.label, x, y, hovered);
  drawSatellites(node, x, y, time);
}

function drawNodeGlow(x, y, radius, pulse, breathe, hovered, colors) {
  const glowRadius = radius + 28 + pulse * 2;
  if (Number.isFinite(x) && Number.isFinite(y) && Number.isFinite(glowRadius) && glowRadius > 0) {
    const gradient = ctx.createRadialGradient(x, y, radius * 0.5, x, y, glowRadius);
    gradient.addColorStop(0, hovered ? colors.ring.replace(/[\d.]+\)$/, '0.3)') : colors.ring);
    gradient.addColorStop(0.5, hovered ? colors.ring.replace(/[\d.]+\)$/, '0.1)') : colors.ring.replace(/[\d.]+\)$/, '0.04)'));
    gradient.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.beginPath();
    ctx.arc(x, y, glowRadius, 0, Math.PI * 2);
    ctx.fillStyle = gradient;
    ctx.fill();
  }
  if (hovered) {
    ctx.beginPath();
    ctx.arc(x, y, radius + 18 + pulse, 0, Math.PI * 2);
    ctx.strokeStyle = colors.ring.replace(/[\d.]+\)$/, `${(0.15 + breathe * 0.15).toFixed(2)})`);
    ctx.lineWidth = 0.8;
    ctx.stroke();
  }
}

function drawNodeSphere(x, y, radius, pulse, breathe, hovered, colors) {
  const renderedRadius = radius + pulse * 0.3;
  if (Number.isFinite(radius) && radius > 0) {
    const sphere = colors.sphere;
    const fill = ctx.createRadialGradient(x - radius * 0.35, y - radius * 0.35, radius * 0.05, x, y, renderedRadius);
    fill.addColorStop(0, hovered ? sphere[0] : sphere[1]);
    fill.addColorStop(0.4, hovered ? sphere[1] : sphere[2]);
    fill.addColorStop(0.85, hovered ? sphere[2] : sphere[3]);
    fill.addColorStop(1, sphere[3]);
    ctx.beginPath();
    ctx.arc(x, y, renderedRadius, 0, Math.PI * 2);
    ctx.fillStyle = fill;
    ctx.fill();

    const specular = ctx.createRadialGradient(x - radius * 0.28, y - radius * 0.3, 0, x - radius * 0.28, y - radius * 0.3, radius * 0.45);
    specular.addColorStop(0, hovered ? colors.spec.replace(/[\d.]+\)$/, '0.22)') : colors.spec);
    specular.addColorStop(0.5, hovered ? colors.spec.replace(/[\d.]+\)$/, '0.06)') : colors.spec.replace(/[\d.]+\)$/, '0.02)'));
    specular.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.beginPath();
    ctx.arc(x, y, renderedRadius, 0, Math.PI * 2);
    ctx.fillStyle = specular;
    ctx.fill();

    ctx.beginPath();
    ctx.arc(x, y, renderedRadius - 1, Math.PI * 0.1, Math.PI * 0.65);
    ctx.strokeStyle = hovered ? colors.rim.replace(/[\d.]+\)$/, `${(0.14 + breathe * 0.1).toFixed(2)})`) : colors.rim;
    ctx.lineWidth = hovered ? 1.5 : 0.8;
    ctx.stroke();
  }

  ctx.beginPath();
  ctx.arc(x, y, renderedRadius, 0, Math.PI * 2);
  ctx.strokeStyle = hovered ? colors.glow : colors.base;
  ctx.lineWidth = hovered ? 1.2 : 0.5;
  ctx.stroke();
  if (hovered) {
    ctx.beginPath();
    ctx.arc(x, y, radius - 3, -Math.PI * 0.8, -Math.PI * 0.2);
    ctx.strokeStyle = 'rgba(63,252,176,0.12)';
    ctx.lineWidth = 1.2;
    ctx.stroke();
  }
}

function drawNodeLabel(label, x, y, hovered) {
  ctx.font = hovered ? '600 14px "Rubik"' : '500 12px "Rubik"';
  ctx.fillStyle = hovered ? '#e0ecd8' : '#4a6858';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(label, x, y);
}
let hoveredNode = null;
let satProgress = 0;
const canvas = document.getElementById('c');
const ctx = canvas.getContext('2d');
let W;
let H;
let ghosts = [];
let stars = [];
let time = 0;
let activeNode = null;

function resize() {
  W = canvas.width = window.innerWidth;
  H = canvas.height = window.innerHeight;
  ghosts = makeGhosts(W, H);
  stars = makeStars(W, H);
}

function nodePos(node) {
  return { x: node.x * W, y: node.y * H };
}

function satPos(node, index, total, progress) {
  const { x, y } = nodePos(node);
  const angle = (index / total) * Math.PI * 2 - Math.PI / 2;
  const orbitRadius = (node.r + 60) * progress;
  return {
    x: x + Math.cos(angle) * orbitRadius,
    y: y + Math.sin(angle) * orbitRadius,
  };
}

function drawCenterHint() {
  if (activeNode) return;
  ctx.font = 'italic 300 10px "Noto Serif"';
  ctx.fillStyle = '#1e2a20';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText('explore', W / 2, H / 2);
}

function draw() {
  try {
    ctx.clearRect(0, 0, W, H);
    time += 0.016;
    drawStars(time);
    ghosts.forEach(ghost => drawGhost(ghost, time));
    if (mapReady) {
      drawConnections(time);
      const target = hoveredNode ? 1 : 0;
      satProgress += (target - satProgress) * 0.08;
      acts.forEach((node, index) => drawNode(node, index, time));
      drawCenterHint();
    }
  } catch (error) {
    console.error('draw:', error);
  }
  requestAnimationFrame(draw);
}

function isSatHovered(node, index) {
  if (!node?.satellites.length) return false;
  const position = satPos(node, index, node.satellites.length, satProgress);
  const radius = node.satellites[index].r * satProgress;
  return Math.hypot(MX - position.x, MY - position.y) < radius + 10;
}

resize();
window.addEventListener('resize', resize);
const miniCanvas = document.getElementById('mini-canvas');
const mctx = miniCanvas.getContext('2d');
const MS = 120;

function drawMini() {
  mctx.clearRect(0, 0, MS, MS);

  // subtle circle bg
  mctx.beginPath();
  mctx.arc(MS/2, MS/2, MS/2 - 1, 0, Math.PI * 2);
  mctx.fillStyle = 'rgba(14,15,12,0.85)';
  mctx.fill();
  mctx.strokeStyle = '#1a2a1e';
  mctx.lineWidth = 0.5;
  mctx.stroke();

  // connections
  connections.forEach(([a, b]) => {
    const na = acts.find(n => n.id === a);
    const nb = acts.find(n => n.id === b);
    mctx.beginPath();
    mctx.moveTo(na.x * MS, na.y * MS);
    mctx.lineTo(nb.x * MS, nb.y * MS);
    mctx.strokeStyle = '#182218';
    mctx.lineWidth = 0.4;
    mctx.stroke();
  });

  // nodes
  acts.forEach(n => {
    const mx = n.x * MS, my = n.y * MS;
    const isActive = n === activeNode;
    const r = isActive ? 6 : 4;
    mctx.beginPath();
    mctx.arc(mx, my, r, 0, Math.PI * 2);
    mctx.fillStyle = isActive ? '#1D9E75' : '#0f1a10';
    mctx.fill();
    mctx.strokeStyle = isActive ? '#9fcfbc' : '#1a3025';
    mctx.lineWidth = 0.5;
    mctx.stroke();
  });

  // satellites of active
  if (activeNode && activeNode.satellites.length > 0) {
    const mx = activeNode.x * MS, my = activeNode.y * MS;
    for (let si = 0; si < activeNode.satellites.length; si += 1) {
      const baseAngle = (si / activeNode.satellites.length) * Math.PI * 2 - Math.PI / 2;
      const orbitR = 18;
      const sx = mx + Math.cos(baseAngle) * orbitR;
      const sy = my + Math.sin(baseAngle) * orbitR;
      mctx.beginPath();
      mctx.arc(sx, sy, 3, 0, Math.PI * 2);
      mctx.fillStyle = '#0d5c42';
      mctx.fill();
    }
  }

  requestAnimationFrame(drawMini);
}

// ── interaction ──────────────────────────────────────────
let mapReady = false;
let activeDerivationController = null;

function initMap() {
  if (mapReady) return;
  mapReady = true;
}

// hover detection
canvas.addEventListener('mousemove', () => {
  if (!mapReady) return;
  let found = null;
  acts.forEach(n => {
    const { x, y } = nodePos(n);
    { var d = Math.hypot(MX - x, MY - y); if (d < (n.satellites && n.satellites.length > 0 ? n.r + 80 : n.r + 16)) found = n; }
  });
  hoveredNode = found;
  canvas.style.cursor = found ? 'none' : 'none';
});

// touch detection — update MX/MY from touch coordinates
canvas.addEventListener('touchstart', e => {
  if (!mapReady) return;
  const touch = e.touches[0];
  MX = touch.clientX;
  MY = touch.clientY;

  // find touched node
  let found = null;
  acts.forEach(n => {
    const { x, y } = nodePos(n);
    { var d = Math.hypot(MX - x, MY - y); if (d < (n.satellites && n.satellites.length > 0 ? n.r + 80 : n.r + 20)) found = n; }
  });

  if (found) {
    e.preventDefault();
    if (hoveredNode && hoveredNode.satellites && hoveredNode.satellites.length > 0 && satProgress > 0.5) {
      for (var si2 = 0; si2 < hoveredNode.satellites.length; si2++) {
        if (isSatHovered(hoveredNode, si2)) { openSat(hoveredNode, si2); return; }
      }
    }
    if (found.satellites && found.satellites.length > 0 && hoveredNode !== found) {
      hoveredNode = found;
    } else {
      hoveredNode = found;
      openAct(found);
    }
  }
}, { passive: false });

// click on main canvas
canvas.addEventListener('click', () => {
  if (!mapReady) return;
  // check satellites first
  if (hoveredNode && hoveredNode.satellites.length > 0) {
    for (let si = 0; si < hoveredNode.satellites.length; si++) {
      if (isSatHovered(hoveredNode, si)) {
        openSat(hoveredNode, si);
        return;
      }
    }
  }
  // check primary nodes
  acts.forEach(n => {
    const { x, y } = nodePos(n);
    if (Math.hypot(MX - x, MY - y) < n.r + 16) openAct(n);
  });
});

// click mini map
miniCanvas.addEventListener('mousemove', e => {
  const rect = miniCanvas.getBoundingClientRect();
  const scaleX = MS / rect.width;
  const scaleY = MS / rect.height;
  const mx = (e.clientX - rect.left) * scaleX;
  const my = (e.clientY - rect.top)  * scaleY;
  let over = false;
  acts.forEach(n => {
    if (Math.hypot(mx - n.x * MS, my - n.y * MS) < 18) over = true;
  });
  miniCanvas.style.opacity = over ? '1' : '0.75';
});

miniCanvas.addEventListener('click', e => {
  const rect = miniCanvas.getBoundingClientRect();
  const scaleX = MS / rect.width;
  const scaleY = MS / rect.height;
  const mx = (e.clientX - rect.left) * scaleX;
  const my = (e.clientY - rect.top)  * scaleY;
  acts.forEach(n => {
    const nx = n.x * MS, ny = n.y * MS;
    if (Math.hypot(mx - nx, my - ny) < 18) {
      if (n === activeNode) goToMap();
      else openAct(n);
    }
  });
});

function openAct(node) {
  activeNode = node;
  hoveredNode = null;
  satProgress = 0;
  const titleLines = node.title.split('\n').join('<br>');
  const sAct = document.getElementById('s-act');
  const diagramEl = document.getElementById('act-diagram');
  sAct.scrollTop = 0;
  sAct.style.flexDirection = 'column';
  sAct.style.alignItems = 'center';

  if (node.diagram) {
    // order: title → diagram → step text (body is removed, text comes via steps)
    document.getElementById('act-content').innerHTML = `
      <div class="act-num cv-u-f2ead26c699c">${node.num} — ${node.id}</div>
      <h1 class="act-title cv-u-db14c5d9c854">${titleLines}</h1>
    `;
    diagramEl.style.display = 'block';
    diagramEl.innerHTML = node.diagram;
    sAct.style.overflowY = 'auto';
    sAct.style.overflowX = 'hidden';
    if (node.id === 'chain') setTimeout(() => initDiagramControls('st', chainStepTexts, 8), 50);
    if (node.id === 'security') setTimeout(() => initDiagramControls('sa', securityStepTexts, 6), 50);
  } else {
    document.getElementById('act-content').innerHTML = `
      <div class="act-num cv-u-f2ead26c699c">${node.num} — ${node.id}</div>
      <h1 class="act-title cv-u-db14c5d9c854">${titleLines}</h1>
      ${node.body}
    `;
    diagramEl.innerHTML = '';
    diagramEl.style.display = 'none';
    sAct.style.overflow = 'auto';
  }

  show('s-act');
}

function openSat(node, satelliteIndex) {
  const satellite = node.satellites[satelliteIndex];
  activeNode = node;
  const diagram = document.getElementById('act-diagram');
  const actScreen = document.getElementById('s-act');
  actScreen.scrollTop = 0;
  activeDerivationController = null;

  if (satellite.id === 'utxo-flow') {
    document.getElementById('act-content').innerHTML = `<div class="act-num cv-u-f2ead26c699c">03 — chain ↳ ${satellite.id}</div><h1 class="act-title cv-u-db14c5d9c854">Multi-input transactions<br>and the <em>UTXO model</em></h1>`;
    diagram.style.display = 'block';
    diagram.innerHTML = utxoFlowMarkup;
    actScreen.style.overflowY = 'auto';
    actScreen.style.overflowX = 'hidden';
    setTimeout(() => initDiagramControls('ut', utxoStepTexts, 6), 50);
  } else if (satellite.id === 'key-deriv') {
    document.getElementById('act-content').innerHTML = `<div class="act-num cv-u-9d85d1cda5f9">03 — chain ↳ ${satellite.id}</div>`;
    diagram.style.display = 'block';
    diagram.style.padding = '0 20px';
    diagram.innerHTML = derivationFlowMarkup;
    actScreen.style.overflow = 'hidden';
    document.getElementById('act-wrap').style.paddingTop = '16px';
    actScreen.scrollTop = 0;
    activeDerivationController = mountDerivationFlow(document.getElementById('deriv-root'));
  } else {
    document.getElementById('act-content').innerHTML = `<div class="act-num cv-u-f2ead26c699c">↳ ${satellite.id}</div><h1 class="act-title cv-u-db14c5d9c854">${satellite.label}</h1>`;
    diagram.innerHTML = '';
    diagram.style.display = 'none';
    actScreen.style.overflow = 'auto';
  }
  show('s-act');
}

// escape — back to map
function goToMap() {
  activeNode = null;
  hoveredNode = null;
  activeDerivationController = null;
  document.querySelectorAll('.screen').forEach(screen => screen.classList.remove('on'));
  document.getElementById('mini-map').classList.remove('on');
  document.getElementById('hint').style.opacity = '0';
  document.getElementById('c').style.opacity = '1';
  document.getElementById('act-diagram').style.display = 'none';
  document.getElementById('s-act').classList.remove('has-diagram');
  document.getElementById('act-wrap').style.paddingTop = '';
  document.getElementById('act-diagram').style.padding = '';
}

document.addEventListener('keydown', event => {
  if (event.key === 'Escape') goToMap();
  if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
    if (activeDerivationController) {
      event.preventDefault();
      activeDerivationController.next();
    } else if (document.getElementById('anim-svg')) {
      event.preventDefault();
      stepNext();
    }
  }
  if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
    if (activeDerivationController) {
      event.preventDefault();
      activeDerivationController.previous();
    } else if (document.getElementById('anim-svg')) {
      event.preventDefault();
      stepBack();
    }
  }
});

// hint click also returns
document.getElementById('hint').addEventListener('click', goToMap);

// intro → map
const introHandler = () => {
  initMap();
  document.getElementById('s-intro').classList.remove('on');
  document.getElementById('hint').style.opacity = '0';
  mapReady = true;
};
document.getElementById('s-intro').addEventListener('click', introHandler);
document.getElementById('s-intro').addEventListener('touchend', e => {
  e.preventDefault();
  introHandler();
});

// ── diagram step animation ───────────────────────────────
var utxoStepTexts = ['', 'Your wallet holds multiple UTXOs. Each lives at a different address, a different branch of the key tree. Three envelopes, three locks, three keys \u2014 all from one seed.', 'All inputs get consumed into one transaction. KasSee gathers UTXOs, calculates totals: 3 inputs in, 2 outputs out.', 'Two outputs. One to the recipient. The remainder returns as change minus the fee. The fee is implicit: sum of inputs minus sum of outputs.', 'Each input needs its own signature. Three inputs, three derivation paths, three private keys, three Schnorr signatures.', 'For each input, KasSigner reads the locking script, finds the public key, searches the derivation tree, derives the matching private key, and signs. All inside the air gap.', 'Three 64-byte Schnorr signatures packed into the signed transaction. Each proves you control the key that locked that UTXO. KasSee broadcasts. The network verifies all three.'];
const chainStepTexts = ['', 'Your keys exist in two forms. The public key is known to the network — it lives inside every unspent output (UTXO) as the lock. The private key lives only on KasSigner. It never leaves.', 'Someone wants to send Kaspa. KasSee — running locally on your machine — knows your public key and finds your UTXOs. It builds the unsigned transaction: destination, amount, change.', 'KasSee asks the node for the full UTXO details — the value and the locking script. It needs this to build a valid signature request. Without it, the device cannot sign correctly.', 'KasSee packages the unsigned transaction and the UTXO data together and sends everything to KasSigner as a QR code. The public key travels with it.', 'KasSigner receives the package and builds the sighash — a Blake2b digest that binds the amount, the destination, and the locking script into a single 32-byte fingerprint. This is what will be signed.', 'Before signing anything, KasSigner shows you the amount and the recipient address on its own screen. A screen that has never touched the internet. You verify. You confirm physically.', 'Only after your confirmation does KasSigner use the private key. Schnorr signature over the sighash digest. The private key is used and stays. It does not leave the device.', 'The signature returns to KasSee via QR. KasSee broadcasts the complete transaction to the network. The node verifies the signature against the UTXO lock. If it matches — the funds move.'];
const securityStepTexts = ['', 'Stolen SD card. No device needed — just grab the card. Three barriers. AES-256-GCM encryption — without the password, the data is noise. Steganographic hiding — the encrypted seed lives inside a JPEG photo as EXIF metadata. Thousands of photos, nobody knows which one matters. BIP39 passphrase — even if someone gets the 24 words, those words lead to a decoy wallet. The real funds live behind a passphrase that exists only in your memory. Blocked.', 'Physical access, device powered off. The attacker has the hardware. But the keys lived in volatile RAM. Power is gone. SRAM decays in milliseconds. There is nothing to extract. Blocked.', 'Physical access, device powered on. The only vulnerable state. Keys are in RAM. An attacker with lab equipment — voltage glitching, cold boot probes, EM side-channel — could theoretically extract them. JTAG is permanently disabled via eFuse. The window is as long as the device stays on with a seed loaded. Mitigation: sign, then power off immediately.', 'Fake firmware. Cloned repo, phishing download, modified binary — you install without checking. Three barriers. Docker verification — build it yourself, compare the SHA-256 hash. eFuse Secure Boot — the ROM rejects anything not signed with the RSA-3072 key burned into silicon. Schnorr signature — firmware checks its own hash at every boot. Blocked.', 'Malware QR or SD card. Craft a payload that exploits a parser bug to execute arbitrary code. Every parser in the signing path is safe Rust — zero unsafe blocks. Out-of-bounds access triggers a controlled panic. The panic handler wipes all RAM before halting. No code execution. Blocked.', 'KasSee phishing. Cloned web app or browser malware modifies the transaction. The screen shows the right address, but the QR contains a different one — the attacker gets paid instead of you. Defense: verify the destination on the KasSigner screen. The device shows what is actually in the data. Five attacks blocked by technology. One requires the user to look.'];
let currentStep = 0;
let currentPrefix = 'st';
let currentTexts = chainStepTexts;
let currentTotal = 8;

function updateSteps() {
  for (let i = 0; i <= currentTotal; i++) {
    const el = document.getElementById(currentPrefix + i);
    if (el) el.classList.toggle('on', i <= currentStep);
  }
  const lbl = document.getElementById('step-label');
  const btnB = document.getElementById('btn-back');
  const btnN = document.getElementById('btn-next');
  const txt = document.getElementById('step-text');
  if (lbl) lbl.textContent = 'step ' + currentStep + ' of ' + currentTotal;
  if (btnB) { btnB.disabled = currentStep === 0; btnB.style.opacity = currentStep === 0 ? '0.3' : '1'; }
  if (btnN) { btnN.disabled = currentStep === currentTotal; btnN.style.opacity = currentStep === currentTotal ? '0.3' : '1'; btnN.textContent = currentStep === currentTotal ? 'done ✓' : 'next →'; }
  if (txt) {
    txt.style.opacity = '0';
    setTimeout(() => {
      txt.textContent = currentTexts[currentStep] || '';
      txt.style.opacity = currentTexts[currentStep] ? '1' : '0';
    }, 200);
  }
  if (currentStep === 1) {
    const sAct = document.getElementById('s-act');
    const wrap = document.getElementById('act-wrap');
    if (sAct && wrap) setTimeout(() => sAct.scrollTo({ top: wrap.offsetHeight, behavior: 'smooth' }), 100);
  }
}

function stepNext() { if (currentStep < currentTotal) { currentStep++; updateSteps(); } }
function stepBack() { if (currentStep > 0) { currentStep--; updateSteps(); } }

function initDiagramControls(prefix, texts, total) {
  currentPrefix = prefix;
  currentTexts = texts;
  currentTotal = total;
  currentStep = 0;
  updateSteps();
  const svg = document.getElementById('anim-svg');
  const btnN = document.getElementById('btn-next');
  const btnB = document.getElementById('btn-back');
  if (svg) svg.addEventListener('click', stepNext);
  if (btnN) btnN.addEventListener('click', e => { e.stopPropagation(); stepNext(); });
  if (btnB) btnB.addEventListener('click', e => { e.stopPropagation(); stepBack(); });
}

// start loops
draw();
drawMini();

// ── tooltip touch support ────────────────────────────────
document.addEventListener('click', e => {
  const tip = e.target.closest('.tool-tip');
  document.querySelectorAll('.tool-tip.active').forEach(el => {
    if (el !== tip) el.classList.remove('active');
  });
  if (tip) {
    e.preventDefault();
    e.stopPropagation();
    tip.classList.toggle('active');
  }
});
