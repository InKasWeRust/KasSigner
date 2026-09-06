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
