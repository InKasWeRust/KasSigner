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
