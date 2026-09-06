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
