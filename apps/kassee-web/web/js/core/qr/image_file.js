const MAX_IMAGE_BYTES = 16 * 1024 * 1024;
const MAX_DECODE_SIDE = 2048;

function validateImageFile(file) {
    if (!file) throw new Error('Choose a QR image file first');
    if (file.size > MAX_IMAGE_BYTES) throw new Error('QR image is larger than 16 MiB');
    if (file.type && !file.type.startsWith('image/')) throw new Error('The selected file is not an image');
}

async function loadImage(file) {
    if (typeof createImageBitmap === 'function') return createImageBitmap(file);

    const objectUrl = URL.createObjectURL(file);
    try {
        const image = new Image();
        image.decoding = 'async';
        image.src = objectUrl;
        await image.decode();
        return image;
    } finally {
        URL.revokeObjectURL(objectUrl);
    }
}

function scaledDimensions(width, height) {
    if (!width || !height) throw new Error('The selected image has no readable dimensions');
    const scale = Math.min(1, MAX_DECODE_SIDE / Math.max(width, height));
    return {
        width: Math.max(1, Math.round(width * scale)),
        height: Math.max(1, Math.round(height * scale)),
    };
}

export async function decodeQrImageFile(file) {
    validateImageFile(file);
    if (typeof jsQR !== 'function') throw new Error('The QR decoder is unavailable');

    const image = await loadImage(file);
    try {
        const sourceWidth = image.width || image.naturalWidth;
        const sourceHeight = image.height || image.naturalHeight;
        const dimensions = scaledDimensions(sourceWidth, sourceHeight);
        const canvas = document.createElement('canvas');
        canvas.width = dimensions.width;
        canvas.height = dimensions.height;
        const canvasContext = canvas.getContext('2d', { willReadFrequently: true });
        if (!canvasContext) throw new Error('The browser could not create an image decoder canvas');
        canvasContext.drawImage(image, 0, 0, dimensions.width, dimensions.height);
        const pixels = canvasContext.getImageData(0, 0, dimensions.width, dimensions.height);
        return jsQR(pixels.data, pixels.width, pixels.height, {
            inversionAttempts: 'attemptBoth',
        });
    } finally {
        if (typeof image.close === 'function') image.close();
    }
}
