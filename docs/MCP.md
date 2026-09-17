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

## The two modes, and why the default is the quiet one

The sheet asks one question: **who can reach the port**.

**Nobody** is the default. The listener binds `127.0.0.1`, so the port is not on
the network at all — not on your Wi-Fi, not anywhere — and your computer reaches
it through `adb forward`. That used to mean a USB cable, which is why it was not
the default. Since Android 11 it does not: *Wireless debugging* attaches adb
over Wi-Fi after a one-time pairing, and `adb forward` then works exactly as it
does on a cable. See **Getting your computer in** below; it is three commands,
once.

**Anyone on this Wi-Fi** is the other answer, and it is there because it needs
nothing set up at all. It binds **one real network interface** — the Wi-Fi
address the phone already has — so a laptop on the same network can reach it
with no platform-tools. That is a genuinely different security position:

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
conference — do not use it.** Nothing on the phone can make a plaintext port on
a hostile network safe, and the mode that puts nothing on the network costs one
pairing.

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
3. Choose who can reach the port — **Nobody** (the default; the port stays on
   `127.0.0.1`) or **Anyone on this Wi-Fi** — and decide whether to allow
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

## Getting your computer in

In the default mode the port is on `127.0.0.1`, so something has to carry port
8765 on your computer through to port 8765 on the phone. That something is
`adb forward` — and since Android 11 it does not need a cable.

`adb forward` is a **host-side** command. The adb server on your computer opens
a local listening socket and proxies each accepted connection over whichever
transport that device is attached on; `adbd` opens the matching connection on
the device. Nothing in it is USB-specific. Attach the device over Wi-Fi and the
forward behaves exactly as it does on a cable.

### Over Wi-Fi, with no cable

On the phone: **Settings > System > Developer options > Wireless debugging**,
on. The MCP sheet has an **Open wireless debugging** row that goes straight
there.

Then, on your computer, three commands — the sheet has each of them with the
real numbers filled in and a copy button:

```
adb pair 192.168.1.42:41234       # the PAIRING dialog's port, then its code
adb connect 192.168.1.42:37129    # the Wireless debugging screen's port
adb forward tcp:8765 tcp:8765
```

**The two ports are different and neither is fixed.** This is the thing people
get wrong, and it is worth being precise about:

* The **pairing** port belongs to the *Pair device with pairing code* dialog,
  not to `adbd`. It appears when you open that dialog, beside a six-digit code,
  and both die when you close it. Run `adb pair` while the dialog is still on
  screen, and type the code when adb asks.
* The **connect** port belongs to `adbd`, is printed on the Wireless debugging
  screen under this device's name, and lasts as long as wireless debugging is
  on. It changes whenever wireless debugging is switched off and on, and across
  reboots. **The sheet finds this one for you**: `adbd` advertises an
  `_adb-tls-connect._tcp` service on the device, and reading it needs no
  permission, no root and no Shizuku.

Nocturne deliberately does *not* try to show the pairing port. It exists only
while a dialog that covers this app is on screen, so any number captured would
already be dead by the time you were looking at it — and the dialog prints it
next to the code you have to read from there anyway.

Pairing is once per computer. `adb connect` is once per session, or after a
reboot or a change of network. `adb forward` is the one you re-run most: it is
gone when adb restarts, when the phone reboots and when the connection drops.
`adb forward --list` says whether it is there.

### What that buys

Against **Anyone on this Wi-Fi**, this is better on every axis but one.

* The MCP port is never bound to a network address at all. Nothing but this
  device can open it, whatever else is on the Wi-Fi and whoever else is on it.
* What crosses the network is adb's own connection, and that is **TLS**. The
  six-digit code is a SPAKE2 password: it authenticates the pairing and is never
  itself sent over the wire, and what it establishes is a mutually-authenticated
  channel only a computer you have paired can open. The traffic that is plain
  HTTP in the other mode is encrypted here.
* Everything else is unchanged: the 256-bit token, the constant-time compare,
  the backoff, the twenty-failure shutdown, the read-only default.

The one axis it loses on: you need `adb` on your computer — Android
platform-tools — and the other mode needs nothing at all.

### Over a cable instead

With a USB cable and USB debugging on, skip the first two commands:

```
adb forward tcp:8765 tcp:8765
```

If a cable and a wireless connection are both attached, adb will ask which
device you mean. Name it — `adb -s 192.168.1.42:37129 forward tcp:8765 tcp:8765`
— or `adb -d` for the USB one.

---

## Claude Code

Claude Code speaks Streamable HTTP natively. One command, with the address and
token from the sheet:

```
claude mcp add --transport http nocturne http://127.0.0.1:8765/mcp \
  --header "Authorization: Bearer PASTE_THE_TOKEN_HERE"
```

Or, as a block in `.mcp.json` (project scope) or `~/.claude.json` (user scope):

```json
{
  "mcpServers": {
    "nocturne": {
      "type": "http",
      "url": "http://127.0.0.1:8765/mcp",
      "headers": { "Authorization": "Bearer PASTE_THE_TOKEN_HERE" }
    }
  }
}
```

The host is `127.0.0.1` because `adb forward` put the port on your own machine.
In **Anyone on this Wi-Fi** mode, substitute the phone's address instead —
`http://192.168.1.42:8765/mcp`. The sheet always prints the right one.

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
        "-y", "mcp-remote", "http://127.0.0.1:8765/mcp",
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
  unless you say this. With the default mode the URL *is* localhost, so this
  one is only strictly needed in **Anyone on this Wi-Fi** mode; leaving it in
  costs nothing and means the block works either way.
* `--transport http-only` — stops it probing first for the deprecated HTTP+SSE
  transport, which this server does not offer.
* `Authorization:${AUTH}` with the value in `env`, and **no space after the
  colon** — several clients fail to quote an argument containing a space when
  they spawn `npx`, and the token arrives mangled. Putting the value in the
  environment sidesteps it.

Restart Claude Desktop completely after editing the file.

---

## Why not HTTPS

Short version: **there is no HTTPS path that current MCP clients will accept
from this device, so in *Anyone on this Wi-Fi* mode the traffic is plaintext and
the token is the protection.** In the default mode the question does not arise:
the HTTP never leaves the device, and what does cross the network is adb's own
TLS connection.

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
the network, use the default mode — `adb` brings the encryption that this
server cannot.

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
2. **The forward is not there.** In the default mode this is nearly always it.
   `adb forward tcp:8765 tcp:8765` must have been run in the *current* adb
   session; check with `adb forward --list` and look for `tcp:8765 tcp:8765`.
   If it is empty, run it again. `adb devices` should show the phone as
   `device`, not `unauthorized` and not `offline` — an `offline` wireless
   device needs `adb connect` again, with the port re-read from the Wireless
   debugging screen, because it will have changed.
3. **Is the address still right?** *Anyone on this Wi-Fi* mode only. The
   phone's Wi-Fi address changes when it changes network and can change on its
   own DHCP lease. Re-read it from the sheet; if it differs from your config,
   update the config.
4. **Are you on the same network?** Not just "both on Wi-Fi" — a guest network,
   a second SSID, or a VPN on the laptop puts you somewhere else. This applies
   to the wireless-debugging route too: `adb connect` has to reach the phone.
5. **Client isolation.** Many public and some home access points block traffic
   between their clients ("AP isolation", "client isolation"). **Wireless
   debugging does not get past this** — `adb connect` is computer-to-phone
   traffic like any other, so it is blocked exactly as the MCP port was.
   Nothing on the phone can change it. What does work:
   * a **USB cable**, which is not on that network at all; or
   * the **phone's own hotspot**, joined from the computer. Traffic to the
     access point is not traffic between its clients, so isolation does not
     apply — and Nocturne will name the interface `Hotspot` in the sheet.
   * failing both, a network you control.

### `adb pair` fails, or the pairing dialog gives up

1. **The dialog was closed.** The pairing server lives inside the *Pair device
   with pairing code* dialog. Close it and the port and the code are both gone,
   and `adb pair` gets a connection refused. Open the dialog, then run the
   command, and leave it up until adb prints `Successfully paired`.
2. **The wrong port.** The pairing port and the connect port are different
   numbers on the same address. `adb pair` wants the one printed *in the
   dialog*; the one on the screen behind it is for `adb connect`.
3. **The code expired.** The dialog rotates the code. Re-open it and use what
   it shows now.
4. **Old platform-tools.** `adb pair` arrived in platform-tools 30.0.0. `adb
   --version` below that has no `pair` subcommand at all.

### The sheet says the connect port was `not found`

The sheet asks the device for the `_adb-tls-connect._tcp` service `adbd`
advertises. Not finding it is not an error you have to fix — the number is
printed on the Wireless debugging screen, and typing it in is all the sheet
would have saved you. It happens when:

* wireless debugging is off (the chip beside it usually says so);
* the scan ran before `adbd` had advertised — tap **rescan**;
* this build's mDNS stack does not report locally-registered services, which
  varies by manufacturer and by Android release.

The **wireless debugging** chip is read from a system setting that is not part
of the public SDK, so a device that does not carry it says `unknown` rather
than guessing.

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
| `triage` | One orientation pass: imports grouped by interest (crypto, anti-debug, JNI, networking, process/exec), the hottest functions by incoming xref, and the most notable strings. Where to dig. |
| `list_functions` | List or search functions. `scope=loaded` searches the loaded set and sorts by address, name, size or call-graph degree; `scope=all` pages the whole binary in address order via the engine, so every function is reachable. Paginated. |
| `list_strings` | Recovered strings with their addresses. Paginated, substring search. |
| `list_symbols` | Imports or exports. Paginated, substring search. |
| `disassemble_function` | Instructions with bytes, mnemonic, operands, the engine's auto-comments and yours. Paginated. |
| `decompile_function` | Pseudo-C, with the Ghidra p-code backend or the built-in IR lifter. |
| `decompile_functions` | Decompile a batch — an address list, or an offset+count window over the whole function list — in one call, each row identical to `decompile_function`'s. Bounded by a function count and a total size, and reports how far it got. |
| `xrefs` | References in and out of a function, with the call site and the owning function. Paginated. |
| `find_string_xrefs` | Given the address of a string or datum — not a function — the functions that reference it, each with the referencing site. The direct route from a string to the routine that uses it; the data-aware counterpart to `xrefs`. Paginated. |
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

The whole binary is reachable without pulling it all at once. A large library
loads only its first several thousand functions into the app; `list_functions`
with `scope=all` pages the engine's entire function list in address order (its
answer adds `scanned` and `functionsTotal`), and `decompile_functions` sweeps
that same list in bounded batches. Both keep every answer capped and report the
total, so a walk always knows how much remains. The recovered-strings list is
the one that does not page beyond what the analysis holds — the engine exposes
no whole-binary string cursor — and `list_strings` says so in its `coverage`
line when there are more.
