import { byId } from '../dom.js';

export function visibleScreenName(fallback = 'welcome') {
    const active = document.querySelector('.screen.active');
    return active?.id?.replace(/^screen-/, '') || fallback;
}

export function activateScreen(name) {
    const target = byId(`screen-${name}`);
    if (!target) return false;
    document.querySelectorAll('.screen').forEach(screen => screen.classList.remove('active'));
    target.classList.add('active');
    return true;
}

export function setScreenReturn(screenName, returnScreen) {
    const screen = byId(`screen-${screenName}`);
    if (!screen) return;
    const target = returnScreen && returnScreen !== screenName ? returnScreen : 'welcome';
    screen.dataset.returnScreen = target;
}

export function takeScreenReturn(screenName, fallback = 'welcome') {
    const screen = byId(`screen-${screenName}`);
    const target = screen?.dataset.returnScreen || fallback;
    if (screen) delete screen.dataset.returnScreen;
    return target === screenName ? fallback : target;
}
