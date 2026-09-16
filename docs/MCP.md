# Driving Nocturne from an AI client

Nocturne can expose its analysis engine as an **MCP server**: a client on your
computer — Claude Code, Claude Desktop, anything that speaks the Model Context
Protocol — connects to the phone and calls typed tools that list functions,
decompile them, follow cross-references, read bytes and run the emulator.

**Nocturne contains no assistant.** There is no model client in the app, no API
key, no "explain this function" button, and nothing here sends your binary
anywhere on its own. This is the other end of the wire. The model runs on your
machine, in your client, under your account, and reaches the engine only through
the tools listed at the bottom of this page.

---

## Read this before you turn it on

By default the server binds **one real network interface** — the Wi-Fi address
the phone already has — so a laptop on the same network can reach it with no
cable and no platform-tools. That is convenient, and it is a genuinely different
security position from a loopback port:

* Anyone on the same network can reach the port.
* **The bearer token is the only thing stopping them.** It is 256 random bits,
  new on every start, never written to disk, and compared in constant time, so
  it is not going to be guessed — but it is the whole boundary, so do not paste
  it into anything you would not paste a password into.
* **The traffic is not encrypted.** Requests and answers are plain HTTP. What
  crosses the network is the token in a header, and disassembly, decompiled
  source, strings and raw bytes of the binary you have open. Anyone who can see
  your network traffic can read all of it. There is no practical TLS option that
  today's MCP clients will accept from a device with a DHCP address and a
  self-signed certificate — see *Why not HTTPS* below.

**On a network you do not control — a café, a hotel, an office guest VLAN, a
conference — use the loopback mode instead.** It binds `127.0.0.1`, nothing off
the phone can reach it, and a USB cable plus `adb forward` gets your desktop in.
It is two extra commands and it removes the entire network exposure.

What is on your side either way:

| | |
|---|---|
| Off by default | Nothing starts it but a tap. No launch check, no boot receiver, `START_NOT_STICKY` so Android will not restart it. |
| One address, never `0.0.0.0` | Either loopback, or one interface that the app names in the sheet. |
| Visible while running | A foreground-service notification for as long as the port is open, naming the interface and address, with a Stop button. |
| Read-only by default | The three tools that write to your project are not even advertised unless you switch writes on before starting. |
| No filesystem access | No tool takes a path. Everything works on the binary you opened in the app. |
| Idle stop | Thirty minutes with no request and the listener shuts itself down. |
| Attack stop | Twenty requests with a bad token and it shuts down and says so. |
| Closes with the app | Swiping Nocturne away, or closing its main screen, takes the listener with it. |

The app **cannot tell you which Wi-Fi network you are on**. Naming an SSID
requires the location permission on modern Android, and Nocturne does not ask
for it. It shows you the interface and the address and says so plainly — you are
the one who knows whether that network is yours.

---

## Turning it on

1. Open the binary you want to work on, on the phone. The server only ever
   exposes what is already open; it cannot open a file for you.
2. Overflow menu (or the command palette, Ctrl+K) → **MCP server**.
3. Choose **This network** or **This device only**, and decide whether to allow
   writes. Both are fixed for the life of the session — a client caches the tool
   list, so they cannot move underneath it.
4. Turn **Run the server** on. Allow the notification when asked; refusing it
   does not stop the server, it only hides the one thing that tells you the port
   is open.
5. The sheet now shows the address, the token, a QR code carrying both, and a
   ready-to-paste block for each client.

The QR encodes `http://ADDRESS:8765/mcp#token=TOKEN`. The token rides in the URL
fragment, which is never sent to a server — it is a carrier for the two values
your client needs, nothing more.

---

## Claude Code

Claude Code speaks Streamable HTTP natively. One command, with the address and
token from the sheet:

```
claude mcp add --transport http nocturne http://192.168.1.42:8765/mcp \
  --header "Authorization: Bearer PASTE_THE_TOKEN_HERE"
```

Or, as a block in `.mcp.json` (project scope) or `~/.claude.json` (user scope):

```json
{
  "mcpServers": {
    "nocturne": {
      "type": "http",
      "url": "http://192.168.1.42:8765/mcp",
      "headers": { "Authorization": "Bearer PASTE_THE_TOKEN_HERE" }
    }
  }
}
```

Check it with `/mcp` inside Claude Code, or `claude mcp list` outside it.

The token changes every time you restart the server, so the entry has to be
updated each session. `claude mcp remove nocturne` and re-add, or edit the
header in place.

---

## Claude Desktop

Claude Desktop starts local MCP servers as processes rather than connecting to
URLs, so it reaches this one through the **mcp-remote** bridge, which proxies
stdio to Streamable HTTP. It needs Node installed.

In `claude_desktop_config.json` (Settings → Developer → Edit Config):

```json
{
  "mcpServers": {
    "nocturne": {
      "command": "npx",
      "args": [
        "-y", "mcp-remote", "http://192.168.1.42:8765/mcp",
        "--allow-http", "--transport", "http-only",
        "--header", "Authorization:${AUTH}"
      ],
      "env": { "AUTH": "Bearer PASTE_THE_TOKEN_HERE" }
    }
  }
}
```

Three details in there are load-bearing:

* `--allow-http` — mcp-remote refuses a plain-HTTP URL that is not localhost
  unless you say this.
* `--transport http-only` — stops it probing first for the deprecated HTTP+SSE
  transport, which this server does not offer.
* `Authorization:${AUTH}` with the value in `env`, and **no space after the
  colon** — several clients fail to quote an argument containing a space when
  they spawn `npx`, and the token arrives mangled. Putting the value in the
  environment sidesteps it.

Restart Claude Desktop completely after editing the file.

---

## Loopback mode, over a cable

Pick **This device only** in the sheet before starting. The address becomes
`127.0.0.1`, and nothing on the network can reach the port at all. Then, on the
computer, with the phone connected by USB and USB debugging on:

```
adb forward tcp:8765 tcp:8765
```

Every config block above stays exactly the same except the host:

```
http://127.0.0.1:8765/mcp
```

The forward is per-connection: it is gone when you unplug the phone, when adb
restarts, and when the phone reboots. Re-run it after any of those.

---

## Why not HTTPS

Short version: **there is no HTTPS path that current MCP clients will accept
from this device, so the traffic is plaintext and the token is the protection.**

The reasons, since it matters:

* A certificate has to name the address it serves. The phone's address comes
  from DHCP and changes between networks and often between days, so any
  certificate generated on the device would be stale a lot of the time.
* A self-signed certificate is rejected by both clients. Claude Code has no
  option to trust one or to skip verification for an MCP server. `mcp-remote`
  runs under Node, so `NODE_EXTRA_CA_CERTS` in the config's `env` can make
  Claude Desktop trust a CA you install — but that means generating a CA on the
  phone, exporting it, installing it on the desktop and keeping the leaf
  certificate in step with a changing IP, and Claude Code's handling of that
  variable has been inconsistent across versions.

Shipping a setup that looks encrypted and fails at connection time would be
worse than saying this plainly. If your threat model includes anyone watching
the network, use loopback mode and the cable.

The app's `res/xml/network_security_config.xml` keeps
`cleartextTrafficPermitted="false"` for the whole app, and that is unchanged:
that policy governs the platform's HTTP stacks (the updater's HTTPS calls) and
by Android's own documentation is not applied to raw `Socket`/`ServerSocket`,
which cannot know whether what it carries is cleartext. Nothing here weakens the
app's outbound network policy.

---

## Troubleshooting

### "Connection refused" or the client shows the server as failed

Work down this list:

1. **Is the server actually running?** The sheet says `listening` and there is a
   notification in the status bar. If it stopped by itself the sheet says why —
   idle timeout, bad tokens, or the app's main screen being closed.
2. **Is the address still right?** The phone's Wi-Fi address changes when it
   changes network and can change on its own DHCP lease. Re-read it from the
   sheet; if it differs from your config, update the config.
3. **Are you on the same network?** Not just "both on Wi-Fi" — a guest network,
   a second SSID, or a VPN on the laptop puts you somewhere else.
4. **Client isolation.** Many public and some home access points block traffic
   between clients ("AP isolation", "client isolation"). Nothing on the phone
   can fix this. Use loopback mode and a cable.
5. **Loopback mode without the forward.** In loopback mode, `adb forward
   tcp:8765 tcp:8765` must have been run in the current adb session. Check with
   `adb forward --list`; you should see `tcp:8765 tcp:8765`. If it is empty, run
   it again. `adb devices` should show your phone as `device`, not
   `unauthorized`.

### 401 Unauthorized

The token is wrong, missing, or stale. In order of likelihood:

1. **The server was restarted.** A new token is generated every single start.
   The old one will never work again. Copy the current one out of the sheet.
2. **The header is malformed.** It must be exactly
   `Authorization: Bearer <token>` — the word `Bearer`, one space, then the
   43-character token with nothing around it. A trailing newline from a copy is
   the usual culprit.
3. **The variable did not expand.** Claude Code does not expand environment
   variables inside a project `.mcp.json`'s headers, so
   `"Bearer ${SOMETHING}"` arrives at the server as the literal text. Paste the
   token, or use the `claude mcp add --header` form.
4. **`npx` mangled the argument.** If you wrote `--header "Authorization: Bearer
   abc"` with a space and it fails, switch to the `env` form shown above.

The sheet counts every refusal and logs where it came from. If that number is
climbing and it is not you, something on that network is probing the port —
stop the server.

### The tools all answer "No binary is open in Nocturne"

Exactly what it says. Open something on the phone. No tool here can open a file;
that is deliberate, and it is why a client cannot reach anything you have not
chosen to look at.

### The write tools are missing

The server was started read-only, which is the default. Stop it, switch **Let
the client write to this project** on, start it again — and re-pair, because
stopping the server rotates the token.

---

## The tools

Read-only, always available:

| Tool | What it does |
|---|---|
| `analysis_overview` | Format, architecture, entry, base, sections, segments, counts, decompiler state. Call this first. |
| `list_functions` | List or search functions. Paginated, sortable by address, name, size or call-graph degree. |
| `list_strings` | Recovered strings with their addresses. Paginated, substring search. |
| `list_symbols` | Imports or exports. Paginated, substring search. |
| `disassemble_function` | Instructions with bytes, mnemonic, operands, the engine's auto-comments and yours. Paginated. |
| `decompile_function` | Pseudo-C, with the Ghidra p-code backend or the built-in IR lifter. |
| `xrefs` | References in and out of a function, with the call site and the owning function. Paginated. |
| `call_graph` | A bounded neighbourhood around one function, or the busiest functions in the binary. |
| `read_memory` | Bytes as hex and ASCII, by virtual address or file offset. |
| `emulate_function` | Run one function under the p-code emulator and read back what it wrote. |
| `list_annotations` | The renames, comments, bookmarks and notes already recorded on this project. |

Only when writes are allowed:

| Tool | What it does |
|---|---|
| `rename_function` | Name a function in the project database. |
| `set_comment` | Comment an address. An empty string removes it. |
| `add_bookmark` | Bookmark an address with a label. |

All three write to Nocturne's own SQLite project database, exactly like typing
the same thing on the phone — they appear in every panel, export to the
IDAPython and IDC scripts, and roll back with the app's own undo. **None of them
modify the binary on disk.**

Every list is paginated the same way: `offset` and `limit` going in, and
`total`, `count` and `nextOffset` coming back. A binary here can carry well over
a thousand functions and twelve thousand call edges — page through them, do not
try to pull them all into one answer.
