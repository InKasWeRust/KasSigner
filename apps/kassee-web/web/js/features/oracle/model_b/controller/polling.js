// Oracle Model B polling facade.
import { createOracleRendering } from './polling/render.js';
import { createOracleBlockWatcher } from './polling/block_watcher.js';
import { createOracleRefresh } from './polling/refresh.js';

export function createOraclePolling() {
    const rendering = createOracleRendering();
    const blockWatcher = createOracleBlockWatcher(rendering.oracleMbRenderState);
    const refresh = createOracleRefresh({ ...rendering, ...blockWatcher });
    return { ...rendering, ...blockWatcher, ...refresh };
}
