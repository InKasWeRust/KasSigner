import { toast } from '../../../../core/ui/toast.js';

export function downloadCovenantExport(covenant, payload) {
    const blob = new Blob([payload.bytes], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    const type = (covenant.type || 'covenant').replace(/[^a-z0-9-]/g, '');
    anchor.href = url;
    anchor.download = `cov-${type}-${covenant.address.slice(-8)}${payload.extension}`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    toast(`Saved ${anchor.download}`, 'ok', 2000);
}
