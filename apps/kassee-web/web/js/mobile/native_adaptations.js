// Shared KasSee mobile adaptations. Native shells provide only tiny bridge callbacks.
const STYLE_ID = 'kassigner-mobile-adaptations';
const MOBILE_TAB_ID = 'gear-tab-mobile';
const EMPTY_IMPORT_CLASS = 'kassigner-mobile-empty-import';
let activeBridge = null;
let emptyImportObserver = null;
let resetHandlerInstalled = false;

function ensureStyle() {
  if (document.getElementById(STYLE_ID)) return;
  const style = document.createElement('style');
  style.id = STYLE_ID;
  style.textContent = '@media (max-width:420px){.header-status .label{display:none!important}.header-status{gap:0!important}} '
    + '.gear-menu-tabs{overflow-x:auto!important;overflow-y:hidden!important;-webkit-overflow-scrolling:touch;overscroll-behavior-x:contain;scrollbar-width:none;touch-action:pan-x;flex-wrap:nowrap!important}'
    + '.gear-menu-tabs::-webkit-scrollbar{display:none}.gear-menu-tabs .gear-tab{flex:0 0 auto!important;min-width:82px}'
    + '#screen-kpub-manager.kassigner-mobile-empty-import .kpub-manager-list-card{display:none!important}';
  document.head.appendChild(style);
}

function syncEmptyImport() {
  const screen = document.getElementById('screen-kpub-manager');
  const form = document.getElementById('kpub-import-form');
  const list = document.getElementById('kpub-saved-list');
  const count = Number.parseInt(document.getElementById('kpub-saved-count')?.textContent || '', 10);
  const empty = Number.isFinite(count) ? count === 0 : !list?.querySelector('.kpub-entry');
  screen?.classList.toggle(EMPTY_IMPORT_CLASS, Boolean(empty && form && !form.classList.contains('hidden')));
}

function ensureEmptyImportObserver() {
  if (emptyImportObserver) return;
  emptyImportObserver = new MutationObserver(syncEmptyImport);
  for (const id of ['kpub-saved-count', 'kpub-saved-list', 'kpub-import-form']) {
    const node = document.getElementById(id);
    if (node) emptyImportObserver.observe(node, { childList: true, subtree: true, attributes: true, characterData: true });
  }
  syncEmptyImport();
}

function ensureResetHandler() {
  if (resetHandlerInstalled) return;
  resetHandlerInstalled = true;
  addEventListener('kassee:request-runtime-reset', event => {
    if (!activeBridge?.resetWalletSurface) return;
    event.preventDefault();
    activeBridge.resetWalletSurface();
  });
}

function ensureMobileTab() {
  const tabs = document.querySelector('.gear-menu-tabs');
  if (!tabs || document.getElementById(MOBILE_TAB_ID)) return;
  const button = document.createElement('button');
  button.type = 'button';
  button.id = MOBILE_TAB_ID;
  button.className = 'gear-tab';
  button.textContent = 'Mobile';
  button.addEventListener('click', () => {
    document.querySelectorAll('.gear-tab').forEach(item => item.classList.remove('active'));
    button.classList.add('active');
    document.getElementById('gear-menu')?.classList.remove('visible');
    document.getElementById('btn-header-settings')?.classList.remove('active');
    activeBridge?.openMobileSettings?.();
  });
  tabs.appendChild(button);
}

export function installMobileAdaptations(bridge) {
  activeBridge = bridge;
  ensureStyle();
  ensureEmptyImportObserver();
  ensureResetHandler();
  ensureMobileTab();
}
