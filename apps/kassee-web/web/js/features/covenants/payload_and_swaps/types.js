export const COVENANT_TYPE_CODES = Object.freeze({
    additive: 0x06,
    escrow: 0x07,
    'timelocked-escrow': 0x08,
    'oracle-v1': 0x09,
    'private-swap': 0x0B,
    crowdfund: 0x0C,
    'merkle-whitelist': 0x0D,
    payjoin: 0x0F,
    treasury: 0x10,
    deposit: 0x11,
    'commit-reveal': 0x14,
    dms: 0x18,
    'global-spending-limit': 0x19,
    'global-allowance': 0x1A,
    'timelocked-savings': 0x1B,
});

export const COVENANT_TYPES_BY_CODE = Object.freeze(
    Object.fromEntries(Object.entries(COVENANT_TYPE_CODES).map(([name, code]) => [code, name])),
);
