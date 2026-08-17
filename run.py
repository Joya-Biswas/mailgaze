#!/usr/bin/env python3
"""
Mailgaze entry point.

This script starts the FastAPI application with Uvicorn,
with automatic reload enabled for development.
"""

import os
import sys

import uvicorn

# Locally this stays on the loopback address so the server isn't exposed to the
# network by accident. A host platform sets PORT (and needs 0.0.0.0 to route
# traffic into the container), so both are read from the environment.
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))

# Auto-reload watches the filesystem and restarts on every change: useful while
# writing code, wasteful and slightly risky anywhere else.
DEV_MODE = os.environ.get("MAILGAZE_ENV", "development").lower() != "production"

BANNER_WIDTH = 60
BANNER_LINES = ("Mailgaze", "Email Header Forensics")


def build_banner(ascii_only: bool = False) -> str:
    """
    Build the startup banner, centered inside a box.

    Args:
        ascii_only: Use plain ASCII box characters instead of box-drawing
            characters, for consoles that can't encode them.

    Returns:
        The banner as a multi-line string.
    """
    if ascii_only:
        corner_top = corner_bottom = "+" + "-" * BANNER_WIDTH + "+"
        side = "|"
    else:
        corner_top = "╔" + "═" * BANNER_WIDTH + "╗"
        corner_bottom = "╚" + "═" * BANNER_WIDTH + "╝"
        side = "║"

    body = "\n".join(
        f"{side}{line.center(BANNER_WIDTH)}{side}" for line in BANNER_LINES
    )

    return (
        f"\n{corner_top}\n{body}\n{corner_bottom}\n\n"
        f"Starting server at http://{HOST}:{PORT}\n\n"
        "Open your browser and paste email headers to analyze them.\n"
        "Press Ctrl+C to stop the server.\n"
    )


def print_banner() -> None:
    """
    Print the startup banner, degrading to ASCII on limited consoles.

    Windows consoles default to a legacy codepage (cp1252) that cannot encode
    box-drawing characters, so printing them raises UnicodeEncodeError.
    """
    try:
        print(build_banner())
    except UnicodeEncodeError:
        print(build_banner(ascii_only=True))


def main() -> None:
    """Start the Mailgaze server with a friendly banner."""
    print_banner()
    sys.stdout.flush()

    # Run the FastAPI app via Uvicorn
    uvicorn.run(
        "app.main:app",
        host=HOST,
        port=PORT,
        reload=DEV_MODE,  # Auto-reload on code changes, development only
    )


if __name__ == "__main__":
    main()
