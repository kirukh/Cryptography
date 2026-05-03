"""
Gemeinsame Hilfsfunktionen fuer alle Statefulness-Demos.

Liefert konsistentes Output-Format ueber alle vier Demos hinweg.
"""
from __future__ import annotations
import hashlib
import textwrap


# ANSI-Farben - funktioniert in WSL-Terminal, in VSCode-Terminal,
# und in Windows Terminal. Falls du auf einem Terminal ohne ANSI-Support
# bist (selten), kannst du USE_COLOR auf False setzen.
USE_COLOR = True

C_RESET   = "\033[0m"  if USE_COLOR else ""
C_BOLD    = "\033[1m"  if USE_COLOR else ""
C_DIM     = "\033[2m"  if USE_COLOR else ""
C_RED     = "\033[31m" if USE_COLOR else ""
C_GREEN   = "\033[32m" if USE_COLOR else ""
C_YELLOW  = "\033[33m" if USE_COLOR else ""
C_BLUE    = "\033[34m" if USE_COLOR else ""
C_MAGENTA = "\033[35m" if USE_COLOR else ""
C_CYAN    = "\033[36m" if USE_COLOR else ""


def banner(title: str, char: str = "=") -> None:
    bar = char * 70
    print(f"\n{C_BOLD}{C_CYAN}{bar}\n  {title}\n{bar}{C_RESET}\n")


def section(title: str) -> None:
    print(f"\n{C_BOLD}{C_BLUE}--- {title} ---{C_RESET}")


def info(msg: str) -> None:
    print(f"  {msg}")


def good(msg: str) -> None:
    print(f"  {C_GREEN}[OK]{C_RESET} {msg}")


def bad(msg: str) -> None:
    print(f"  {C_RED}[!!]{C_RESET} {msg}")


def warn(msg: str) -> None:
    print(f"  {C_YELLOW}[!]{C_RESET} {msg}")


def explain(text: str) -> None:
    """Mehrzeilige Erklaerung mit Einrueckung."""
    wrapped = textwrap.fill(
        textwrap.dedent(text).strip(),
        width=68,
        initial_indent="  ",
        subsequent_indent="  ",
    )
    print(f"{C_DIM}{wrapped}{C_RESET}")


def fingerprint(data: bytes, n: int = 12) -> str:
    """Kurzer Hash-Fingerprint, um Aenderungen visuell sichtbar zu machen."""
    return hashlib.sha256(data).hexdigest()[:n]


def show_bytes(label: str, data: bytes, show_first: int = 16) -> None:
    """Zeigt Anfang und Fingerprint eines Byte-Strings."""
    head = data[:show_first].hex()
    print(f"  {label:18s} sha256={fingerprint(data)} "
          f"len={len(data)} head={head}...")


def takeaway(text: str) -> None:
    """Hervorgehobener Lernziel-Punkt am Ende einer Demo."""
    print(f"\n{C_BOLD}{C_MAGENTA}>> Takeaway:{C_RESET}")
    wrapped = textwrap.fill(
        textwrap.dedent(text).strip(),
        width=68,
        initial_indent="     ",
        subsequent_indent="     ",
    )
    print(wrapped)
