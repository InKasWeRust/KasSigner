import { generate_qr_frames, generate_qr_svg_text } from '../../../../wasm/api.js';

export function presentExportQr(area, payload, onError) {
    if (payload.hex.length <= 268) {
        try {
            area.replaceChildren(qrCard(generate_qr_svg_text(payload.hex), 'Scan with KasSigner to store on SD'));
            return () => {};
        } catch (error) {
            onError(error);
            return () => {};
        }
    }

    try {
        const frames = JSON.parse(generate_qr_frames(payload.hex));
        let index = 0;
        let playing = true;
        const render = () => renderFrame(area, frames, index, playing, actions);
        const actions = {
            previous: () => { index = (index - 1 + frames.length) % frames.length; render(); },
            next: () => { index = (index + 1) % frames.length; render(); },
            toggle: () => { playing = !playing; render(); },
        };
        render();
        const timer = setInterval(() => {
            if (!playing) return;
            index = (index + 1) % frames.length;
            render();
        }, 1600);
        return () => clearInterval(timer);
    } catch (error) {
        onError(error);
        return () => {};
    }
}

function renderFrame(area, frames, index, playing, actions) {
    const wrapper = qrCard(frames[index].svg, `Frame ${index + 1}/${frames.length}`);
    const controls = document.createElement('div');
    controls.className = 'cov-export-qr-controls';
    controls.append(
        controlButton('◀◀', actions.previous),
        controlButton(playing ? '⏸' : '▶', actions.toggle),
        controlButton('▶▶', actions.next),
    );
    wrapper.appendChild(controls);
    area.replaceChildren(wrapper);
}

function qrCard(svg, caption) {
    const wrapper = document.createElement('div');
    wrapper.className = 'cov-export-qr-card';
    const image = document.createElement('div');
    image.className = 'cov-export-qr-image';
    image.innerHTML = svg;
    const label = document.createElement('div');
    label.className = 'cov-export-qr-caption';
    label.textContent = caption;
    wrapper.append(image, label);
    return wrapper;
}

function controlButton(label, action) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'cov-export-qr-control';
    button.textContent = label;
    button.addEventListener('click', action);
    return button;
}
