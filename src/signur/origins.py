"""Which origins a browser may talk to Signur from.

A browser attaches the session cookie to whatever a page asks of us, and a
WebSocket handshake is not protected by the same-origin policy the way an
ordinary fetch is: the origin has to be checked here. When a deployment lists
its origins we honour that list exactly. When it lists none — the single
machine install, where there is nothing to configure — the only origin that
makes sense is the address Signur was reached at. A caller that sends no origin
at all is not a browser, so it carries no session of somebody else's to abuse.
"""

from signur.config import Settings


def origin_is_trusted(origin: str, host: str, settings: Settings) -> bool:
    origin = origin.rstrip("/")
    if settings.allowed_origins:
        return origin in settings.allowed_origins
    if not origin:
        return True
    return origin in {f"http://{host}", f"https://{host}"}
