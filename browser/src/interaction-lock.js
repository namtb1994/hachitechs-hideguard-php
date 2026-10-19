export function createInteractionLock() {
    var locked = false,
        gate,
        changed = new Set(),
        initialBodyLock = document.body.hasAttribute('data-hachitech-ab-inert');

    function sync() {
        if (!locked) {
            changed.forEach(function (element) {
                element.removeAttribute('inert');
            });
            changed.clear();
            return;
        }
        Array.from(document.body.children).forEach(function (element) {
            if (element === gate || element.contains(gate) || element.hasAttribute('inert')) {
                return;
            }
            element.setAttribute('inert', '');
            changed.add(element);
        });
    }

    function setLocked(value, element) {
        locked = value;
        gate = element;
        document.documentElement.classList.toggle('hachitech-ab-locked', locked);
        sync();
    }

    function guard(event) {
        if (locked && !(gate && gate.contains(event.target))) {
            event.preventDefault();
            event.stopImmediatePropagation();
        }
    }

    ['click', 'dblclick', 'pointerdown', 'touchstart', 'submit', 'keydown'].forEach(function (name) {
        document.addEventListener(name, guard, {capture: true, passive: false});
    });
    new MutationObserver(sync).observe(document.body, {childList: true});
    gate = document.getElementById('hachitech-ab-gate');
    setLocked(initialBodyLock || Boolean(gate && !gate.hidden), gate);
    if (initialBodyLock) {
        // Hand off the server-rendered body lock after its children are locked.
        document.body.removeAttribute('inert');
        document.body.removeAttribute('data-hachitech-ab-inert');
    }
    return {setLocked: setLocked};
}
