# blackbar clipboard hotkeys — one shortcut, every interface

The `blackbar` CLI reads text on stdin and writes only the transformed text to
stdout, so it drops straight into a clipboard pipeline. Bind two OS hotkeys and
you get reversible anonymization in **any** app — the Claude Chrome extension,
claude.ai web, Office, Claude Desktop, Claude Code, an email client, anywhere.

The flow is always the same:

1. **Before sending** sensitive text → run it through `blackbar enc` → paste the
   `<ENC:…>` version into the model.
2. **After the model answers** with tokens → copy the answer → run `blackbar dec`
   → read the restored values locally.

The model only ever sees tokens; the key and the originals never leave your
machine.

## One-time setup

```sh
# 1. Put the launcher on PATH (adjust the path to your clone)
ln -s "$PWD/bin/blackbar" ~/.local/bin/blackbar

# 2. Create a persistent key (needed to decrypt later — back it up)
blackbar keygen

# 3. Make sure the Presidio analyzer is running (detection only)
docker compose -f plugins/blackbar/docker-compose.yml up -d
```

Detection language defaults to `en`; set `PRESIDIO_GUARD_LANGUAGE=es` (or pass
`--language es`) for Spanish, etc.

## macOS (pbcopy / pbpaste)

Encrypt / decrypt the clipboard in place:

```sh
pbpaste | blackbar enc | pbcopy     # anonymize what you're about to paste
pbpaste | blackbar dec | pbcopy     # de-anonymize the copied answer
```

Bind them with a tool like **Automator → Quick Action → Run Shell Script**, or
**Raycast/Alfred/skhd**. Example skhd bindings:

```
cmd + shift + e : /bin/sh -lc 'pbpaste | blackbar enc | pbcopy'
cmd + shift + d : /bin/sh -lc 'pbpaste | blackbar dec | pbcopy'
```

## Linux — Wayland (wl-clipboard)

```sh
wl-paste | blackbar enc | wl-copy
wl-paste | blackbar dec | wl-copy
```

## Linux — X11 (xclip or xsel)

```sh
xclip -selection clipboard -o | blackbar enc | xclip -selection clipboard
xclip -selection clipboard -o | blackbar dec | xclip -selection clipboard
```

Bind these to keys in your desktop's keyboard settings, or with `sxhkd`:

```
super + shift + e
    sh -c 'xclip -selection clipboard -o | blackbar enc | xclip -selection clipboard'
super + shift + d
    sh -c 'xclip -selection clipboard -o | blackbar dec | xclip -selection clipboard'
```

## Windows (PowerShell)

```powershell
Get-Clipboard | blackbar enc | Set-Clipboard
Get-Clipboard | blackbar dec | Set-Clipboard
```

Bind via AutoHotkey:

```ahk
^+e:: RunWait, powershell -NoProfile -Command "Get-Clipboard | blackbar enc | Set-Clipboard",, Hide
^+d:: RunWait, powershell -NoProfile -Command "Get-Clipboard | blackbar dec | Set-Clipboard",, Hide
```

## Notes

- `blackbar dec` only restores tokens whose key matches; a wrong key leaves them
  as `<ENC:…>` and never guesses. So decrypting someone else's tokens, or with
  the wrong key, simply does nothing.
- Detection is best-effort (Presidio is high-recall, not perfect). Review before
  sending anything truly sensitive.
- This is ToS-clean on a Pro/Max subscription: it never touches your login token
  and never proxies traffic — it only transforms text locally.
