#!/usr/bin/env python3
"""Render the Telegram welcome/help caption for the decoder bot."""

from __future__ import annotations

import argparse
import html
import re


SUPPORTED_FORMATS = (
    (".ehi", "HTTP Injector"),
    (".npvt", "NPV Tunnel"),
    (".hc", "HTTP Custom"),
    (".dark", "Dark Tunnel"),
    (".nm", "NetMod"),
    (".tnl", "OpenTunnel"),
    (".ziv", "ZIVPN"),
    (".hat", "HAT Tunnel"),
    (".sip", "SocksIP / SocksTunnel"),
    (".ssc", "SSC Custom / raw hex"),
    (".sks", "SocksHTTP"),
)


def _safe(value: str, fallback: str, limit: int = 64) -> str:
    value = value.strip()[:limit]
    return html.escape(value, quote=False) if value else fallback


def _display_name(first_name: str, last_name: str, username: str) -> str:
    full_name = " ".join(part.strip() for part in (first_name, last_name) if part.strip())
    if full_name:
        return html.escape(full_name[:48], quote=False)
    if username.strip():
        return f"@{html.escape(username.strip().lstrip('@')[:48], quote=False)}"
    return "there"


def _badge_name(name: str) -> str:
    cleaned = re.sub(r"^(?:🏅\s*)+|(?:\s*🏅)+$", "", name).strip()
    return f"🏅{cleaned or 'there'}🏅"


def render_caption(
    first_name: str = "",
    last_name: str = "",
    username: str = "",
    user_id: str = "",
    command: str = "/start",
) -> str:
    name = _display_name(first_name, last_name, username)
    badge_name = _badge_name(name)
    safe_id = _safe(user_id, "Not provided")
    format_lines = "\n".join(
        f"• <code>{extension.strip()}</code> — {description}"
        for extension, description in SUPPORTED_FORMATS
    )
    caption = f"""🔐 <b>ReversalX VPN Decode Bot</b> 🔐

👋 Welcome, <b>{badge_name}</b>!

🧩 Send a supported VPN configuration file and receive a decrypted readable result.

👤 <b>Your Session</b>
🔹 User: <b>{badge_name}</b>
🔹 ID: <code>{safe_id}</code>
🔹 Status: ✅ Active

✨ <b>Supported Formats</b>
{format_lines}

🚀 <b>How to Use</b>
Send a supported vpn file → wait → receive the result.

📌 <b>Commands</b>
/start — show this welcome
/help — show formats and usage

⚠️ <i>Only decode files you own or are authorized to inspect.</i>"""

    if len(caption) > 1024:
        raise ValueError(f"Telegram caption exceeds 1024 characters: {len(caption)}")
    return caption


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--first-name", default="")
    parser.add_argument("--last-name", default="")
    parser.add_argument("--username", default="")
    parser.add_argument("--user-id", default="")
    parser.add_argument("--command", default="/start")
    args = parser.parse_args()
    print(
        render_caption(
            first_name=args.first_name,
            last_name=args.last_name,
            username=args.username,
            user_id=args.user_id,
            command=args.command,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())