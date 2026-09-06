const MAX_FRAME_COUNT = 128;
const MAX_ASSEMBLED_BYTES = 1024 * 1024;

function equalBytes(left, right) {
    if (left.length !== right.length) return false;
    for (let i = 0; i < left.length; i++) {
        if (left[i] !== right[i]) return false;
    }
    return true;
}

export function parseCovenantFrame(raw) {
    if (raw.length < 4) return null;
    const index = raw[0];
    const total = raw[1];
    const fragmentLength = raw[2];
    if (total < 2 || total > MAX_FRAME_COUNT) return null;
    if (index >= total) throw new Error(`Invalid covenant frame index ${index} for ${total} frames`);
    if (fragmentLength === 0 || fragmentLength !== raw.length - 3) {
        throw new Error('Invalid covenant frame length');
    }
    return { index, total, payload: raw.slice(3) };
}

export function addCovenantFrame(accumulator, frame) {
    let state = accumulator;
    if (!state || state.total !== frame.total) {
        state = { total: frame.total, received: new Set(), buffers: new Array(frame.total), byteLength: 0 };
    }

    const existing = state.buffers[frame.index];
    if (existing && !equalBytes(existing, frame.payload)) {
        throw new Error(`Conflicting duplicate covenant frame ${frame.index + 1}`);
    }
    if (!existing) {
        state.buffers[frame.index] = frame.payload;
        state.received.add(frame.index);
        state.byteLength += frame.payload.length;
        if (state.byteLength > MAX_ASSEMBLED_BYTES) throw new Error('Covenant backup exceeds size limit');
    }

    if (state.received.size !== state.total) return { state, assembled: null };
    if (state.buffers.some(buffer => !(buffer instanceof Uint8Array))) {
        throw new Error('Covenant frame set is incomplete');
    }

    const assembled = new Uint8Array(state.byteLength);
    let offset = 0;
    for (const buffer of state.buffers) {
        assembled.set(buffer, offset);
        offset += buffer.length;
    }
    return { state: null, assembled };
}
