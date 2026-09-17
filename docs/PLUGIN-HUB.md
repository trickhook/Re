# Nocturne Plugin Hub

A community plugin registry that lives entirely in this GitHub repo as JSON — no
server. Authors write NocturneScript plugins in the app, sign them with a
per-device key, and submit them as GitHub issues. A GitHub Action verifies each
submission and opens a pull request; once merged, the plugin is in the registry
the app browses and installs from.

There is no backend and no account system of our own. The only account involved
is the submitter's GitHub account, used once to file the issue.

## The plugin file

A plugin is a `.nocturneplugin` file: a JSON object with exactly these six
fields, in this order, and no others.

```json
{
  "id": "xref-hotspots",
  "name": "Xref Hotspots",
  "version": "1.0",
  "author": "Nocturne",
  "description": "One line about what it does.",
  "script": "log(\"hello\")\n"
}
```

- `id` is the identity and the filename stem: `^[a-z0-9](?:[a-z0-9-]{1,38}[a-z0-9])$`
  (lowercase letters, digits, hyphens; 3–40 chars; no leading/trailing hyphen).
- `version` is `MAJOR.MINOR` or `MAJOR.MINOR.PATCH` (digits and dots).
- `script` is NocturneScript — the sandboxed DSL the engine runs (loop-guarded,
  no file/network/exec, analysis operations only).

### Canonical byte form (this is what gets signed)

The device signature is computed over the **exact bytes** of the plugin file, so
the app and CI must serialize a plugin the same way, down to the byte. The
canonical form is precisely what Android's `org.json` `JSONObject.toString(2)`
produces for the six-field object, plus one trailing newline:

- UTF-8; `\n` newlines; 2-space indent.
- Keys in the order `id, name, version, author, description, script`; only those.
- `": "` after each key; a `,` immediately before the newline between entries.
- String escaping: `"`→`\"`, `\`→`\\`, **`/`→`\/`**, and `\b \f \n \r \t` as their
  short forms; any other character ≤ U+001F as `\u00xx` (lowercase hex);
  everything else, including non-ASCII, emitted raw as UTF-8.
- Exactly one trailing `\n`.

The only place this differs from a "plain" `JSON.stringify` / `json.dumps` is the
forward slash: `org.json` escapes `/` as `\/`, so the canonical form does too.
Reference implementations are in the repo: `.github/scripts/canonical.mjs`
(Node, used by CI). Both the app (signing) and CI (verifying) reduce the plugin
to these bytes before hashing or signing.

## Device identity and signature

On first publish the app generates an **EC P-256** key in the Android KeyStore
(alias `nocturne-author-key`) and never regenerates it. From that key:

- **`authorKey`** — the public key as X.509 SubjectPublicKeyInfo (SPKI) DER,
  base64 with no line wraps. This is the author's cryptographic identity.
- **`authorFingerprint`** — SHA-256 of that SPKI DER, hex, first 16 characters.
  This is the short, human-readable id shown in the app ("author fingerprint").
- **`signature`** — ECDSA-SHA256 over the canonical plugin bytes, DER-encoded,
  base64.

Verification (the app on install, CI on submit) recomputes SHA-256 of the file
bytes and checks it against the recorded `sha256`, then verifies `signature`
against `authorKey` over those same bytes. A mismatch is a hard reject.

### What the signature does and does not mean

It proves the plugin is **intact** and was **signed by the holder of that device
key**. That is authorship + integrity. It is honestly **not**:

- a GitHub credential — filing the issue is what authorizes the repo write; and
- a proof the script is safe — it is arbitrary third-party NocturneScript. The
  real guard is the on-device sandbox that runs it (loop-limited, no
  file/network/exec). The app labels installed community plugins accordingly.

## The registry: `plugins/index.json`

```json
{
  "schema": 1,
  "updated": "<ISO-8601 UTC>",
  "plugins": [
    {
      "id": "xref-hotspots",
      "name": "Xref Hotspots",
      "version": "1.0",
      "author": "Nocturne",
      "authorKey": "<base64 SPKI DER>",
      "authorFingerprint": "<hex16>",
      "description": "one line",
      "path": "plugins/community/xref-hotspots.nocturneplugin",
      "sha256": "<hex of the plugin file bytes>",
      "signature": "<base64 ECDSA-SHA256>",
      "submittedAt": "<ISO-8601 UTC>"
    }
  ]
}
```

Plugin files live at `plugins/community/<id>.nocturneplugin` in the canonical
form above. `path` is repo-relative; the app resolves it against the same raw
base URL it uses for `index.json`. If the registry is missing or unreachable,
the app treats it as a normal empty state, not an error.

## Submitting a plugin

1. In the app: build the plugin in the editor, test-run it locally, then
   **Sign + Publish**. The app serializes the canonical file, signs it, and
   opens a prefilled GitHub issue:

   ```
   https://github.com/<owner>/<repo>/issues/new?labels=plugin-submission&title=...&body=...
   ```

   The issue body is one fenced ` ```json ` block:

   ```json
   { "plugin": { ...the .nocturneplugin object... },
     "authorKey": "<base64 SPKI>",
     "signature": "<base64>" }
   ```

2. Filing the issue needs a GitHub account — one time, in the browser the link
   opens. This is the only account step, and it is what authorizes writing to
   the repo. The device signature proves *who authored* the plugin; the GitHub
   account proves *who asked to publish it*. There is no server in between.

3. The `Plugin submission` Action (`.github/workflows/plugin-submission.yml`)
   runs, validates, and comments the outcome on the issue. On success it opens a
   pull request; once a maintainer merges it, the plugin is live.

Submitting by hand is possible too: open a new issue with the **Plugin
submission** template (`.github/ISSUE_TEMPLATE/plugin-submission.yml`), which
carries the `plugin-submission` label and shows the expected JSON shape.

## What CI checks — and what it does not

The Action verifies, and rejects with a specific comment on any failure:

1. Exactly one ` ```json ` block, parseable, with `plugin` / `authorKey` /
   `signature`.
2. Plugin schema: the six fields and only those; `id` and `version` regexes;
   non-empty `name`/`script`; `script` ≤ 64 KiB; canonical file ≤ 128 KiB.
3. **Structural** NocturneScript sanity only: valid UTF-8, non-empty, and
   balanced `{}` and `()` (ignoring `##` line comments and `"…"` strings). This
   is deliberately *not* a language check — CI never runs the script. The
   on-device sandbox is the real guard.
4. `sha256` and ECDSA-P256-SHA256 `signature` verify against `authorKey` over the
   canonical bytes; the key must be P-256.
5. The id-ownership rule below.

On success it writes `plugins/community/<id>.nocturneplugin`, updates
`index.json` (adds or replaces the entry, refreshes `updated`), and opens a PR.
It merges nothing on its own.

## Id ownership (anti-hijack)

An id is owned by the **first device key** that publishes it. A later submission
for the same id is accepted only if it comes from that **same `authorKey`** and
carries a **higher `version`**. A submission for an id already owned by a
different key is rejected. This stops anyone from overwriting someone else's
plugin by reusing its id.

## The example entries and their key

The registry is seeded with two real, verifiable community entries —
`crypto-finder` and `xref-hotspots` — promoted from the app's bundled plugins so
the schema and the in-app browser have something to show and verify against.

They are signed by a **throwaway** EC P-256 key generated in the build sandbox
**for these examples only**. Its public identity is recorded in `index.json`:

- `authorKey`: `MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElQ/QhvplWWkWKsiefhAI19p1LEVMzSQTcfbq2I1cmwPVeXvTHKQhxYXvpC6GfyN6hz7u+cVQJLmGxZTIzLKXZw==`
- `authorFingerprint`: `b5bf9c80badd46f1`

The matching **private key was discarded** and is not in this repository, so no
one can mint new entries under this identity. The app verifies these examples
using the `authorKey` already in `index.json` — no bundled secret is needed. If
you rebuild the examples you will get a new key and new signatures; that is
expected.

## For maintainers

**Pull request, not direct commit.** The Action commits to a per-issue branch
(`plugin-submission/issue-<n>`) and opens a PR rather than pushing to the default
branch. The submitted script is arbitrary third-party code; even though the
signature proves authorship and the sandbox contains execution, a human merge
gate on the live registry gives an auditable diff and a moment to look. To make
publishing fully automatic instead, push to the default branch in the workflow's
"Open / update the pull request" step.

**Required repo settings** (Settings → Actions → General):

- *Workflow permissions* = **Read and write permissions**. Otherwise the
  `GITHUB_TOKEN` cannot push the branch or comment (403). The workflow already
  requests only `contents: write`, `issues: write`, `pull-requests: write`.
- *Allow GitHub Actions to create and approve pull requests* = **enabled**, or
  `gh pr create` fails.

The `issues` trigger runs with the base-repo token even for issues opened by
outside contributors (unlike fork `pull_request` events), so third-party
submissions get a writable token. The untrusted issue body is passed to the
validator only through an environment variable, never spliced into a shell
command.

**Re-running a check:** edit the issue body (fires `issues: edited`) or remove
and re-add the `plugin-submission` label.
