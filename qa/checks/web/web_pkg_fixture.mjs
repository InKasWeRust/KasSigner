import { randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

async function pathExists(target) {
    try {
        await fs.lstat(target);
        return true;
    } catch (error) {
        if (error?.code === 'ENOENT') return false;
        throw error;
    }
}

/**
 * Temporarily move an existing generated web/pkg tree aside for a QA stub.
 *
 * Browser checks need deterministic WASM exports, while the full QA runner may
 * already have built the real package. The swap stays on the same filesystem
 * so the rename is atomic, and restore removes only the temporary package the
 * check created before putting the original tree back unchanged.
 */
export async function isolateWebPackage(pkgDir) {
    const parent = path.dirname(pkgDir);
    const backupDir = path.join(
        parent,
        `.qa-preserved-${path.basename(pkgDir)}-${process.pid}-${randomUUID()}`,
    );
    const hadOriginal = await pathExists(pkgDir);
    if (hadOriginal) await fs.rename(pkgDir, backupDir);

    let restored = false;
    return {
        pkgDir,
        hadOriginal,
        async create() {
            await fs.mkdir(pkgDir, { recursive: true });
            return pkgDir;
        },
        async restore() {
            if (restored) return;
            let cleanupError = null;
            try {
                await fs.rm(pkgDir, { recursive: true, force: true });
            } catch (error) {
                cleanupError = error;
            }

            try {
                if (hadOriginal) await fs.rename(backupDir, pkgDir);
            } catch (restoreError) {
                if (cleanupError) {
                    throw new AggregateError(
                        [cleanupError, restoreError],
                        'Unable to clean the QA web package and restore the generated package',
                    );
                }
                throw restoreError;
            }

            restored = true;
            if (cleanupError) throw cleanupError;
        },
    };
}
