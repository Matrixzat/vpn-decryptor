#!/usr/bin/env python3
"""Render the Telegram caption for a completed decoder job."""

from __future__ import annotations

import argparse
import html
import re


def _display_name(first_name: str, last_name: str, username: str) -> str:
    full_name = " ".join(
        part.strip() for part in (first_name, last_name) if part.strip()
    )
    if full_name:
        return html.escape(full_name[:48], quote=False)
    if username.strip():
        return f"@{html.escape(username.strip().lstrip('@')[:48], quote=False)}"
    return "there"


def _badge_name(name: str) -> str:
    cleaned = re.sub(r"^(?:🏅\s*)+|(?:\s*🏅)+$", "", name).strip()
    return f"🏅{cleaned or 'there'}🏅"


def render_success_caption(
    *,
    filename: str,
    first_name: str = "",
    last_name: str = "",
    username: str = "",
    user_id: str = "",
) -> str:
    safe_filename = html.escape(filename[:180], quote=True)
    safe_id = html.escape(user_id[:64], quote=True) or "Not provided"
    name = _display_name(first_name, last_name, username)
    badge_name = _badge_name(name)

    if user_id.isdigit():
        requested_by = (
            f'<a href="tg://user?id={html.escape(user_id, quote=True)}">'
            f"{badge_name}</a>"
        )
    else:
        requested_by = f"<b>{badge_name}</b>"

    caption = f"""✅ <b>Decrypted Successfully</b>

📄 <b>File:</b> <code>{safe_filename}</code>

👤 <b>Requested by:</b>
{requested_by}
🆔 <b>User ID:</b> <code>{safe_id}</code>

🔐 Your readable decrypted text file is attached below.

🔓 <b>Decryption:</b> <a href="https://t.me/reversalxmods1">@reversalxmods1</a>"""

    if len(caption) > 1024:
        raise ValueError(f"Telegram caption exceeds 1024 characters: {len(caption)}")
    return caption


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--filename", required=True)
    parser.add_argument("--first-name", default="")
    parser.add_argument("--last-name", default="")
    parser.add_argument("--username", default="")
    parser.add_argument("--user-id", default="")
    args = parser.parse_args()
    print(
        render_success_caption(
            filename=args.filename,
            first_name=args.first_name,
            last_name=args.last_name,
            username=args.username,
            user_id=args.user_id,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())