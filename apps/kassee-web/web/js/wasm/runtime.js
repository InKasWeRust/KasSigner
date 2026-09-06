let runtimeState = 'loading';
let runtimeError = '';

export function markWasmReady() {
    runtimeState = 'ready';
    runtimeError = '';
}

export function markWasmFailed(error) {
    runtimeState = 'failed';
    runtimeError = error instanceof Error ? error.message : String(error);
}

export function isWasmReady() {
    return runtimeState === 'ready';
}

export function wasmRuntimeStatus() {
    return { state: runtimeState, error: runtimeError };
}
