/**
 * Audited dynamic-markup boundary.
 *
 * Prefer textContent/DOM construction. This helper exists only for UI fragments
 * that still need a small fixed set of structural elements. Unsafe
 * or unknown elements are replaced by their literal source text; event/style
 * attributes and unsafe URLs are never retained.
 */
const ALLOWED_TAGS = new Set(['DIV','SPAN','STRONG','BR','A','INPUT','BUTTON','LABEL','TEXTAREA','P']);
const ALLOWED_ATTRS = new Set([
    'class','id','title','type','placeholder','value','checked','disabled','href','target','rel',
]);

export function escapeMarkupAsLiteral(markup) {
    return String(markup ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
}

function safeHref(value) {
    try {
        const url = new URL(String(value), document.baseURI || 'https://localhost/');
        return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : '';
    } catch (_) {
        return '';
    }
}

function sanitizeNode(node) {
    if (node.nodeType === Node.TEXT_NODE) return node;
    if (node.nodeType !== Node.ELEMENT_NODE || !ALLOWED_TAGS.has(node.tagName)) {
        return document.createTextNode(node.outerHTML || node.textContent || '');
    }
    for (const attr of [...node.attributes]) {
        const name = attr.name.toLowerCase();
        if (name.startsWith('on') || name === 'style') {
            node.removeAttribute(attr.name);
            continue;
        }
        if (!ALLOWED_ATTRS.has(name) && !name.startsWith('data-')) {
            node.removeAttribute(attr.name);
            continue;
        }
        if (name === 'href') {
            const href = safeHref(attr.value);
            if (href) node.setAttribute('href', href); else node.removeAttribute('href');
        }
    }
    for (const child of [...node.childNodes]) {
        const sanitized = sanitizeNode(child);
        if (sanitized !== child) child.replaceWith(sanitized);
    }
    return node;
}

export function setSafeMarkup(element, markup) {
    if (!element) return;
    const template = document.createElement('template');
    if (!template.content?.childNodes) {
        // Fail closed on non-browser/minimal DOMs: preserve the requested
        // markup visibly as literal text rather than interpreting any tag.
        element.innerHTML = escapeMarkupAsLiteral(markup);
        return;
    }
    // SECURITY: this is the single audited dynamic innerHTML parsing boundary.
    template.innerHTML = String(markup ?? '');
    for (const child of [...template.content.childNodes]) {
        const sanitized = sanitizeNode(child);
        if (sanitized !== child) child.replaceWith(sanitized);
    }
    element.replaceChildren(template.content.cloneNode(true));
}
