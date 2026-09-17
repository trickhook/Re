# The bundled crackme test target

Nocturne ships a tiny native **crackme** inside the APK so you can exercise the
debugger and analyzer end to end without importing anything. It is a small C
program with a hard-coded auth check and two obvious patch points. Nothing about
it is a real credential system — the "secret" is a constant in a toy binary, and
the whole point is that it is easy to find and defeat.

- **Source:** `app/src/main/cpp/samples/crackme.c`
- **Built by:** the NDK, once per ABI (`arm64-v8a`, `x86_64`), beside
  `libnocturne.so`.
- **Shipped at:** `assets/samples/<abi>/crackme` in the APK (generated at build
  time; not committed).

---

## Analysis needs nothing. Running needs Shizuku.

**Analysing** the target — functions, disassembly, strings, xrefs, pseudo-C —
works on any device with nothing connected.

**Running** it under the debugger needs a **Shizuku backend** connected (shell or
root). Nocturne stages the file into `/data/local/tmp`, makes it executable, and
traces it from the privileged process. The in-process **LOCAL** backend
*cannot* execute a file out of app storage and never will — that is Android's
W^X policy, not a missing feature. See `docs/SHIZUKU.md`.

---

## Load it

Either entry point opens the target the same way the file picker opens an
imported binary (it becomes the current file, so every tab and the staged-run
flow work unchanged):

- **Command palette** (`Ctrl+K`): *Load bundled test target*.
- **Home screen** (no file open yet): *Load bundled test target*, under the
  keyboard-shortcut line.

The correct ABI for the device is chosen automatically. On load you land in the
function list with `main`, `verify_key` and the libc imports.

---

## The exercise

### 1. Read the check

Open **`verify_key`** in the function list and read its disassembly. It walks the
key one byte at a time against the constant `"NOCTURNE-2026"`:

- **arm64:** the loaded key byte and expected byte are compared, then a
  conditional branch decides continue-vs-reject:

  ```
  cmp   w8, w9
  b.eq  <continue>      ; bytes equal -> keep checking
  ...
  mov   w0, #0          ; a byte differed
  ret                   ; return 0
  ```

- **x86_64:**

  ```
  cmpl  %ecx, %eax
  je    <continue>      ; bytes equal -> keep checking
  movl  $0, ...         ; a byte differed
  ...                   ; return 0
  ```

Open **`main`** and find where it branches on the result. This is one clean
branch:

- **arm64:** `bl verify_key` then `cbz w0, <denied>` (branch to the DENIED path
  when the result is zero).
- **x86_64:** `callq verify_key`, then `cmpl $0, %eax; je <denied>`.

The strings `NOCTURNE-2026`, `ACCESS GRANTED`, `ACCESS DENIED` and
`flag{n0cturne_branch_flipped}` are all in the **Strings** panel; the secret has
an xref straight into `verify_key`.

### 2. Run it and watch the compare

With a Shizuku backend connected, spawn it (staged): the Debugger tab's **Run**
button, or the Spawn dialog's *Run crackme*. With no argument the key defaults to
empty, so it prints:

```
Nocturne crackme test target
checking key: ""
ACCESS DENIED
```

Set a breakpoint on the compare inside `verify_key`, spawn again, and step: watch
the expected byte (`N`, `O`, `C`, …) meet the empty key's terminator and take the
reject branch.

### 3. Defeat it — two ways

**A. Flip the loop branch (in `verify_key`).** Make the per-byte compare always
take the "bytes equal" path so no key is ever rejected:

- arm64: turn the `b.eq <continue>` guard into an unconditional branch to
  `<continue>`, or `nop` out the reject that follows it.
- x86_64: flip `je` to `jmp`, or `nop` the reject.

Equivalently, **force the whole function to `return 1`** by overwriting its first
instructions with `mov w0, #1 ; ret` (arm64) / `mov eax, 1 ; ret` (x86_64).

**B. Flip the result branch (in `main`).** Leave `verify_key` alone and make
`main` take the GRANTED path regardless:

- arm64: `nop` the `cbz w0, <denied>` (or change it to `cbnz`).
- x86_64: flip the `je <denied>` to `jne`, or `nop` it.

Either patch, spawned again, prints:

```
ACCESS GRANTED
flag{n0cturne_branch_flipped}
```

That flag line is the confirmation: the GRANTED block ran, which only happens
when your patch actually changed control flow. Patch **A** proves you can defeat
the check itself; patch **B** proves you can defeat the decision that consumes
it. Demonstrating both is the point of the target.
