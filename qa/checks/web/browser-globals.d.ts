declare function jsQR(
    data: Uint8ClampedArray,
    width: number,
    height: number,
    options?: { inversionAttempts?: string },
): { binaryData?: number[] | Uint8Array } | null;
