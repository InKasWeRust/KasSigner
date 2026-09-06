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
