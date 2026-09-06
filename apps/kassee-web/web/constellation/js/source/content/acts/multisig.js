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
