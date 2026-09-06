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
