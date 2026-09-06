import { toast } from '../../../../core/ui/toast.js';
import { downloadCovenantExport } from './file_download.js';
import { presentExportQr } from './qr_presenter.js';

export function showCovenantExportModal(covenant, payload) {
    document.getElementById('cov-export-modal')?.remove();
    const modal = document.createElement('div');
    modal.id = 'cov-export-modal';
    modal.className = 'cov-export-modal';

    const panel = document.createElement('div');
    panel.className = 'cov-export-panel';
    panel.append(
        textElement('div', 'cov-export-heading', `${covenant.label || covenant.type} — ${payload.encrypted ? 'Owner Backup' : 'Beneficiary Backup'}`),
        textElement('div', 'cov-export-address', shortAddress(covenant.address)),
        textElement('div', 'cov-export-size', `${payload.bytes.length} bytes${payload.encrypted ? ' encrypted' : ' (invite)'}`),
    );

    const qrArea = document.createElement('div');
    qrArea.id = 'cov-export-qr-area';
    qrArea.className = 'cov-export-qr-area';
    const qrButton = actionButton('📱 Show QR for KasSigner');
    const fileButton = actionButton(`💾 Download ${payload.extension} file`);
    const closeButton = actionButton('Close', 'cov-export-action cov-export-close');
    panel.append(qrArea, qrButton, fileButton, closeButton);
    modal.appendChild(panel);
    document.body.appendChild(modal);

    let stopQr = () => {};
    const close = () => { stopQr(); modal.remove(); };
    qrButton.addEventListener('click', () => {
        stopQr();
        stopQr = presentExportQr(qrArea, payload, error => toast(`QR generation failed: ${error.message}`, 'error'));
        qrButton.hidden = true;
    });
    fileButton.addEventListener('click', () => downloadCovenantExport(covenant, payload));
    closeButton.addEventListener('click', close);
    modal.addEventListener('click', event => { if (event.target === modal) close(); });
}

function actionButton(label, className = 'cov-export-action') {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = className;
    button.textContent = label;
    return button;
}

function textElement(tag, className, text) {
    const element = document.createElement(tag);
    element.className = className;
    element.textContent = text;
    return element;
}

function shortAddress(address) {
    return address.length > 30 ? `${address.slice(0, 18)}...${address.slice(-6)}` : address;
}
