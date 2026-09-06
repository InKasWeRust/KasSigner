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
