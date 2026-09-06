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
