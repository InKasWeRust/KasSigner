let hoveredNode = null;
let satProgress = 0;
const canvas = document.getElementById('c');
const ctx = canvas.getContext('2d');
let W;
let H;
let ghosts = [];
let stars = [];
let time = 0;
let activeNode = null;

function resize() {
  W = canvas.width = window.innerWidth;
  H = canvas.height = window.innerHeight;
  ghosts = makeGhosts(W, H);
  stars = makeStars(W, H);
}

function nodePos(node) {
  return { x: node.x * W, y: node.y * H };
}

function satPos(node, index, total, progress) {
  const { x, y } = nodePos(node);
  const angle = (index / total) * Math.PI * 2 - Math.PI / 2;
  const orbitRadius = (node.r + 60) * progress;
  return {
    x: x + Math.cos(angle) * orbitRadius,
    y: y + Math.sin(angle) * orbitRadius,
  };
}

function drawCenterHint() {
  if (activeNode) return;
  ctx.font = 'italic 300 10px "Noto Serif"';
  ctx.fillStyle = '#1e2a20';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText('explore', W / 2, H / 2);
}

function draw() {
  try {
    ctx.clearRect(0, 0, W, H);
    time += 0.016;
    drawStars(time);
    ghosts.forEach(ghost => drawGhost(ghost, time));
    if (mapReady) {
      drawConnections(time);
      const target = hoveredNode ? 1 : 0;
      satProgress += (target - satProgress) * 0.08;
      acts.forEach((node, index) => drawNode(node, index, time));
      drawCenterHint();
    }
  } catch (error) {
    console.error('draw:', error);
  }
  requestAnimationFrame(draw);
}

function isSatHovered(node, index) {
  if (!node?.satellites.length) return false;
  const position = satPos(node, index, node.satellites.length, satProgress);
  const radius = node.satellites[index].r * satProgress;
  return Math.hypot(MX - position.x, MY - position.y) < radius + 10;
}

resize();
window.addEventListener('resize', resize);
