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
