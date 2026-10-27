"""SV1 - the splash. Animated truecolor gradient over a block logo."""

from __future__ import annotations

import colorsys
import os
import random
import sys
import time

from . import config

ART = (
    "███████╗██╗   ██╗ ██╗",
    "██╔════╝██║   ██║███║",
    "███████╗██║   ██║╚██║",
    "╚════██║╚██╗ ██╔╝ ██║",
    "███████║ ╚████╔╝  ██║",
    "╚══════╝  ╚═══╝   ╚═╝",
)

FALLBACK = (
    "  +--------------------------------------+",
    "  |   S  V  1      ::      B Y  e e . z v z   |",
    "  +--------------------------------------+",
)

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
CYAN = "\x1b[38;2;0;229;255m"
MAGENTA = "\x1b[38;2;255;0;170m"
GREY = "\x1b[38;2;110;120;140m"
WHITE = "\x1b[38;2;240;248;255m"


def enable_vt() -> None:
    """Turn on ANSI escape handling in the Windows console."""
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def _color(r: float, g: float, b: float) -> str:
    return f"\x1b[38;2;{int(r)},{int(g)},{int(b)}m"


def _paint(char: str, ratio: float, glow: float) -> str:
    hue = 0.52 + ratio * 0.34            # cyan -> magenta across the logo
    value = 0.70 + 0.30 * glow
    r, g, b = colorsys.hsv_to_rgb(hue, 0.82 - 0.55 * glow, value)
    return _color(r * 255, g * 255, b * 255) + char


def _frame(head: float, width: int, phase: int) -> list[str]:
    lines = []
    for row, text in enumerate(ART):
        cells = []
        for x, char in enumerate(text):
            if char == " ":
                cells.append(" ")
                continue
            ratio = x / max(1, width - 1)
            distance = abs(x - head)
            glow = max(0.0, 1.0 - distance / 6.0)
            if phase:
                glow = max(glow, 0.35 if random.random() < 0.12 else 0.0)
            cells.append(_paint(char, ratio, glow))
        lines.append("".join(cells) + RESET)
    return lines


def _draw(lines: list[str], first: bool) -> None:
    if not first:
        sys.stdout.write(f"\x1b[{len(lines)}A\r")
    for index, line in enumerate(lines):
        sys.stdout.write("\x1b[2K" + line)
        if index != len(lines) - 1:
            sys.stdout.write("\n")
    sys.stdout.flush()


def _type(text: str, color: str, delay: float) -> None:
    sys.stdout.write("  ")
    for char in text:
        sys.stdout.write(color + char)
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write(RESET + "\n")
    sys.stdout.flush()


def setup_console() -> None:
    """ANSI + UTF-8 before any glyph touches the terminal."""
    enable_vt()
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def safe_text() -> bool:
    encoding = (getattr(sys.stdout, "encoding", "") or "").lower()
    return "utf" in encoding


def show(animate: bool = True) -> None:
    setup_console()

    if not safe_text():
        for line in FALLBACK:
            sys.stdout.write(CYAN + line + RESET + "\n")
        sys.stdout.flush()
        return

    width = max(len(row) for row in ART)

    if not animate or not sys.stdout.isatty():
        for row in ART:
            sys.stdout.write(CYAN + row + RESET + "\n")
        sys.stdout.write(
            f"  {DIM}{GREY}web vulnerability scanner{RESET}"
            f"  {MAGENTA}{BOLD}BY ee.zvz{RESET}\n\n"
        )
        sys.stdout.flush()
        return

    sys.stdout.write("\n")
    _draw(_frame(-8.0, width, phase=0), first=True)
    sys.stdout.write("\n")
    sys.stdout.flush()

    steps = width + 14
    for step in range(steps):
        _draw(_frame(float(step - 8), width, phase=0), first=False)
        time.sleep(config.BANNER_FRAME_DELAY)

    for _ in range(2):
        _draw(_frame(float(width // 2), width, phase=1), first=False)
        time.sleep(0.06)

    _draw(_frame(float(width), width, phase=0), first=False)
    sys.stdout.write("\n")
    sys.stdout.flush()

    _type("w e b   v u l n e r a b i l i t y   s c a n n e r",
          GREY, 0.006)
    _type("B Y   e e . z v z", MAGENTA + BOLD, 0.022)
    sys.stdout.write("\n")
    sys.stdout.flush()
    time.sleep(config.BANNER_TAIL_DELAY)
