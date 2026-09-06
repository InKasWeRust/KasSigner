/** Resolve an element by id without routing a pure lookup through app state. */
export function byId(id) {
    return document.getElementById(id);
}
