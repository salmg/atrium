#!/usr/bin/env python3
"""
Capture the console screenshots the README uses.

    python3 atrium.py serve --port 8788          # in one terminal
    python3 tools/screenshots.py                 # in another

Drives headless Chrome over the DevTools protocol, which is JSON over one
WebSocket — and `websockets` already arrives with `uvicorn[standard]`, which
the web server needs anyway.  A capture step that pulled in Playwright would
put a second browser and a package manager into a repository whose whole point
is running on a bench machine next to a card reader.

Three things it deliberately does not do.

**It does not fake the data.**  Every view is photographed against the real
server answering real requests.  With no reader plugged in the console says so,
honestly, and that is what the pictures show — a screenshot that implied a card
was present when none was would be worse than no screenshot.

**It does not reach past the router.**  Views are switched through the same
`navigate()` the sidebar calls, so a renamed view breaks the capture loudly
instead of producing twelve pictures of the home page.  (That function is
reachable because the scripts are classic, not modules.  The click *listener*
guards on `e.isTrusted`, so a synthetic `element.click()` does nothing at all —
which is the trap this script exists to avoid falling into twice.)

**It does not trust a timer.**  Each view fetches its own data, so the script
waits for the view to become active *and* stop saying "Loading" before it
captures.  A fixed sleep produced a set of screenshots of spinners once.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

try:
    import websockets
except ModuleNotFoundError:  # pragma: no cover - a dependency message, not logic
    sys.exit(
        "This needs the websockets package, which arrives with the web server:\n"
        "    pip install 'uvicorn[standard]'"
    )

HERE = Path(__file__).resolve().parent
OUT = HERE.parent / "doc" / "images"
CONSOLE = os.environ.get("ATRIUM_URL", "http://127.0.0.1:8788/")
DEBUG_PORT = 9334
VIEWPORT = (1440, 900)

CHROME_CANDIDATES = [
    os.environ.get("CHROME"),
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
]

# (file name, view id, what the picture is for).  The order is the order the
# README walks the tool in, not the order of the sidebar.
SHOTS = [
    ("01-mission-control", "home", "the relay pipeline, stage by stage"),
    ("02-host", "host", "the ISO 8583 half"),
    ("03-simtrace", "simtrace", "the contact capture board"),
    ("04-contactless", "nfc", "the contactless half"),
    ("05-trace", "trace", "the live APDU trace"),
    ("06-profile", "profile", "what a card said about itself"),
    ("07-mutations", "mutations", "the mutation rules"),
    ("08-playbooks", "playbooks", "mutation playbooks on disk"),
    ("09-agent", "agent", "the optional model back end"),
    ("10-intel", "intel", "fingerprinted card history"),
    ("11-logs", "logs", "session logs"),
    ("12-settings", "settings", "where the keys and hosts are set"),
]


def find_chrome() -> str:
    for path in CHROME_CANDIDATES:
        if path and Path(path).exists():
            return path
    raise SystemExit(
        "No Chrome found.  Set CHROME to its path.  Looked in:\n  "
        + "\n  ".join(p for p in CHROME_CANDIDATES if p)
    )


def console_is_up() -> bool:
    try:
        with urllib.request.urlopen(CONSOLE, timeout=3) as response:
            return response.status == 200
    except OSError:
        return False


class Chrome:
    """A minimal CDP client: send a method, await its reply."""

    def __init__(self, socket) -> None:
        self.socket = socket
        self.next_id = 1

    async def send(self, method: str, **params):
        message_id = self.next_id
        self.next_id += 1
        await self.socket.send(
            json.dumps({"id": message_id, "method": method, "params": params})
        )
        while True:
            reply = json.loads(await asyncio.wait_for(self.socket.recv(), timeout=30))
            if reply.get("id") != message_id:
                continue  # an event, or a reply to something already answered
            if "error" in reply:
                raise RuntimeError(f"{method}: {reply['error'].get('message')}")
            return reply.get("result", {})

    async def evaluate(self, expression: str):
        result = await self.send(
            "Runtime.evaluate",
            expression=f"(() => {{ {expression} }})()",
            returnByValue=True,
            awaitPromise=True,
        )
        if "exceptionDetails" in result:
            raise RuntimeError(result["exceptionDetails"].get("text", "the page threw"))
        return result.get("result", {}).get("value")

    async def show(self, view: str) -> None:
        """Switch to a view the way the sidebar does, and wait for it to settle."""
        await self.evaluate(f"window.navigate({view!r}); return true;")
        for attempt in range(80):
            state = await self.evaluate(
                "const active = document.querySelector('.view.active');"
                "return active && {id: active.id, loading: /Loading/i.test(active.innerText)};"
            )
            if state and state["id"] == f"view-{view}" and not state["loading"]:
                break
            if attempt == 79:
                got = state["id"] if state else "nothing"
                raise SystemExit(
                    f"view-{view} never settled (showing {got}).  "
                    "Has the view been renamed, or is the server answering?"
                )
            await asyncio.sleep(0.25)
        await asyncio.sleep(0.6)  # let the last fetch paint

    async def shot(self, name: str) -> None:
        result = await self.send("Page.captureScreenshot", format="png")
        (OUT / f"{name}.png").write_bytes(base64.b64decode(result["data"]))
        print(f"  {name}.png")


async def connect() -> Chrome:
    for _ in range(40):
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{DEBUG_PORT}/json", timeout=2
            ) as response:
                targets = json.loads(response.read())
            page = next((t for t in targets if t.get("type") == "page"), None)
            if page and page.get("webSocketDebuggerUrl"):
                socket = await websockets.connect(
                    page["webSocketDebuggerUrl"], max_size=64 * 1024 * 1024
                )
                return Chrome(socket)
        except OSError:
            pass  # Chrome is still starting
        await asyncio.sleep(0.25)
    raise SystemExit("Could not reach Chrome's debugging port.")


async def main() -> None:
    if not console_is_up():
        raise SystemExit(
            f"Nothing is answering at {CONSOLE}.\n"
            "Start the console first:  python3 atrium.py serve --port 8788"
        )

    OUT.mkdir(parents=True, exist_ok=True)
    chrome_path = find_chrome()
    profile = tempfile.mkdtemp(prefix="atrium-shots-")
    width, height = VIEWPORT

    print(f"chrome:  {chrome_path}")
    print(f"console: {CONSOLE}")
    print(f"capturing into {OUT}")

    chrome = subprocess.Popen(
        [
            chrome_path,
            "--headless=new",
            f"--remote-debugging-port={DEBUG_PORT}",
            f"--user-data-dir={profile}",
            f"--window-size={width},{height}",
            "--hide-scrollbars",
            "--no-first-run",
            "--no-default-browser-check",
            "--force-device-scale-factor=1",
            CONSOLE,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        session = await connect()
        await session.send("Page.enable")
        await session.send("Runtime.enable")
        await session.send(
            "Emulation.setDeviceMetricsOverride",
            width=width,
            height=height,
            deviceScaleFactor=1,
            mobile=False,
        )

        # The router has to exist before any of this means anything.  Checking
        # once, by name, turns "twelve identical screenshots" into one sentence.
        for _ in range(40):
            if await session.evaluate("return typeof window.navigate === 'function';"):
                break
            await asyncio.sleep(0.25)
        else:
            raise SystemExit(
                f"{CONSOLE} loaded but has no view router.  "
                "Is that really the ATRIUM console?"
            )

        for name, view, _why in SHOTS:
            await session.show(view)
            await session.shot(name)

        # The same page in the other theme, last, because the toggle is
        # remembered in localStorage and would otherwise colour every shot
        # after the one that flipped it.
        await session.show("home")
        await session.evaluate(
            "const b = [...document.querySelectorAll('button')]"
            ".find(x => /theme/i.test(x.getAttribute('aria-label') || ''));"
            "b && b.click(); return true;"
        )
        await asyncio.sleep(1.0)
        await session.shot("13-dark-mode")

        print("done")
    finally:
        chrome.terminate()
        try:
            chrome.wait(timeout=10)
        except subprocess.TimeoutExpired:
            chrome.kill()
        shutil.rmtree(profile, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(main())
