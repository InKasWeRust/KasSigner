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
