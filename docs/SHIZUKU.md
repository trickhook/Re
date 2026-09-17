# Running a sample on a phone you have not rooted

Nocturne's debugger can run in a **separate process with shell or root
privilege**, using [Shizuku](https://shizuku.rikka.app/). That turns one thing
from impossible into routine: **running and debugging a native binary you
imported through the file picker**, on an ordinary retail phone, with no root
and no unlocked bootloader.

Everything else in the app works exactly as before without it. Shizuku is never
needed to open, analyse, decompile, emulate or export anything. It is needed for
exactly one verb: **execute**.

---

## Why the app cannot just run the file itself

Nocturne targets SDK 35, so Android 10's W^X rule applies in full. An untrusted
app's data directory is labelled `app_data_file`, and since Android 10 that
label carries **no execute permission**. It is not a `chmod` problem — there is
no mode bit that makes it work, and no path inside `/data/data/com.trickhook`
that behaves differently.

The only two things an app process can `execve` are:

* `/system/bin/*` and the rest of the read-only system image, and
* files in its own `nativeLibraryDir`, which is where its own `.so` files live
  and which the installer populates — nothing the app writes at runtime can
  land there.

A sample the user picked lands in the app's cache. The in-process debugger can
therefore set breakpoints in it, decompile it and emulate it, but it can never
start it. That is why the debugger tab has always said it needs a rooted or
debuggable device.

## What Shizuku changes

A Shizuku **user service** runs *your own code* in a process started by the
Shizuku server:

```
(CLASSPATH='<shizuku.apk>' /system/bin/app_process /system/bin \
   --nice-name='com.trickhook:dbg' moe.shizuku.starter.ServiceStarter \
   --token=… --package=com.trickhook --class=com.trickhook.shizuku.NocturneUserService \
   --uid=…)&
```

That process:

* runs as **uid 2000 (shell)** with the adb backend, or **uid 0** with a root or
  Sui backend;
* has **no non-SDK-API restrictions**;
* loads Nocturne's own classes, through
  `createPackageContextAsUser(CONTEXT_INCLUDE_CODE)` and the app's own
  `ClassLoader`.

`shell` may write to `/data/local/tmp`, `chmod +x` there, and
`fork` / `PTRACE_TRACEME` / `exec` its own child. That is precisely the
`gdbserver` / `lldb-server` / `frida-server` workflow, and it is why those tools
work on unrooted phones.

## The limit, stated up front

**`PTRACE_ATTACH` to a process the backend did not start stays root-only.**

`shell` cannot ptrace an app domain without `run-as`, and `run-as` only covers
packages that are themselves debuggable. Attaching to an arbitrary running
process is a root feature and it does not stop being one because Shizuku is
installed. If your Shizuku is started by root — or you use Sui — you get it,
but then you already had root.

The debugger tab does not hide this. On the shell backend the **Attach** button
is disabled, with the reason printed under it, rather than being offered and
then failing.

---

## The three backends

The Debugger tab carries two chips. The second one names the privilege the
Shizuku server actually has, read from `Shizuku.getUid()` rather than guessed.

| | spawn `/system/bin/*` | run an imported sample | attach to a foreign pid |
|---|---|---|---|
| **In-process** (default, no Shizuku) | yes | **no** | same-uid or root only |
| **Shizuku shell** (uid 2000) | yes | **yes** | no |
| **Shizuku root** (uid 0, or Sui) | yes | **yes** | yes |

The protocol is identical in all three. The whole ptrace debugger is one
JSON-string-in / JSON-string-out call, so the AIDL is literally

```aidl
String dbgCmd(String json) = 1;
```

and every op the in-process debugger understands — `spawn`, `attach`, `cont`,
`step`, `bp_add`, `regs`, `read`, `stack`, `threads`, `poll` — works verbatim
across the Binder. Ops whose name starts with `svc.` are the service's own and
never reach the engine.

## Setting it up

1. **Install Shizuku** — <https://shizuku.rikka.app/download/>. It is free and
   open source. The "Get Shizuku" button in the debugger tab opens that page.
2. **Start it.** On Android 11 and later, Shizuku can pair over *Wireless
   debugging* with no cable; otherwise it gives you one `adb shell` command to
   run. **It has to be started again after every reboot** — that is a property
   of adb-granted privilege, not of Shizuku.
3. **Open Nocturne → Debugger**, pick the Shizuku chip, and press **Grant
   permission**. Shizuku asks once.
4. Press **Connect**. The strip reports `uid 2000 (shell) · aarch64 ·
   u:r:shell:s0` when the privileged process is up and the engine is loaded in
   it.
5. Open a sample, then **Spawn → Run &lt;filename&gt;**.

If you grant permission inside Shizuku's own app while Nocturne is open, press
**Re-check**.

## Every state, and what to do about it

| State | What it means | Button |
|---|---|---|
| `SHIZUKU NOT INSTALLED` | Neither Shizuku nor Sui is on the device | **Get Shizuku** → the download page |
| `SHIZUKU NOT RUNNING` | Installed, but not started this boot | **Open Shizuku** |
| `SHIZUKU TOO OLD` | Server predates API v11, or is below v10 | **Open Shizuku** to update |
| `PERMISSION NEEDED` | Running, never asked | **Grant permission** |
| `PERMISSION REFUSED` | You said no; Shizuku will not ask again | **Open Shizuku** and grant it there |
| `READY TO CONNECT` | Granted, privileged process not started | **Connect** |
| `STARTING` | `bindUserService` in flight | — (times out after 20 s) |
| `CONNECTED` | Process up, engine loaded | **Disconnect** |
| `COULD NOT START` | No binder in time, process died on the way up, or the engine would not load | **Try again** |
| `CONNECTION LOST` | Binder died mid-session; the tracee died with it | **Reconnect** |

## Staging, and cleaning up after it

A shell-uid process **cannot read `/data/user/0/com.trickhook`**. So the sample
is not handed over as a path — there is no path the service could open. The
bytes cross the Binder in 256 KiB chunks:

1. `svc.stageBegin` creates `/data/local/tmp/nocturne/<16 hex>/` at mode `0700`
   and opens the destination file. The name is reduced to
   `[A-Za-z0-9._+-]`, with leading dots stripped, so a picked filename cannot
   traverse out of that directory in a process running as shell.
2. `stageChunk` streams the file across.
3. `svc.stageEnd` closes it, checks the byte count against the declared size,
   `chmod`s it to `0700` — owner-only, because `/data/local/tmp` is shared with
   every other shell process on the device — and reads its ELF header.
4. The debugger `spawn`s that path.
5. `svc.unstage` deletes the file and its directory when the session ends.

Cleanup is deliberately covered three times over, because only one of these is
the tidy path:

* **`svc.unstage`** on kill, on a new spawn, on an attach, and on a backend
  switch;
* **`destroy()`**, which Shizuku calls when the service is unbound, sweeps
  everything and then `System.exit`s;
* **a sweep on every fresh connect**, which is what actually catches the case
  where the app was force-stopped or the phone ran out of battery mid-session.

The sweep only ever touches `/data/local/tmp/nocturne`. It `lstat`s that path
first and refuses to run if it is a symbolic link — with a root backend the
delete runs as uid 0, and a symlink planted there by anything else with shell
access would otherwise redirect it. The recursion uses `lstat` throughout, so a
symlinked child is unlinked rather than followed.

Where the staged file is, is printed in the strip while one exists.

## Honest failure

Every failing path names itself and says what it means.

| Failure | What you see |
|---|---|
| Wrong ABI | `built for arm; the privileged process is aarch64 and this device has no 32-bit runtime. Nothing here can execve it.` |
| A `.so` rather than a program | `shared object with no PT_INTERP: this is a library, not a program.` |
| Not an ELF at all | `no ELF magic. The ptrace backend runs native ELF binaries only…` |
| `/data/local/tmp` not writable | `cannot create … — uid 2000 may not write to /data/local/tmp` |
| Bind timeout | `No binder after 20 s. Shizuku could not start the process, or R8 stripped NocturneUserService out of the release build` |
| Binder death mid-command | `shizuku: the privileged process died while the command was in flight` |
| SELinux denial on spawn/ptrace | the engine's own `strerror` text, e.g. `attach failed: Operation not permitted` |
| Engine did not load | the exact `UnsatisfiedLinkError` text, plus which of the two load attempts produced it |

The service never throws across the Binder. An exception there would arrive as a
bare `RemoteException` with no message, and the tab would say "command failed"
and stop; instead everything is caught and returned as
`{"ok":false,"error":"<kind>: <why>"}`, which the existing parser and event log
already handle.

---

## The dependency

`dev.rikka.shizuku:api` and `dev.rikka.shizuku:provider`, both **13.1.5**, both
**MIT** ([LICENSE](https://github.com/RikkaApps/Shizuku-API/blob/master/LICENSE)).
MIT sits fine beside this app's own MIT licence and the Apache-2.0 (Ghidra) and
BSD-3 (Capstone) code already vendored under `app/src/main/cpp`.

These are the **first third-party Gradle dependencies this project has added**.
The MCP server, the QR encoder, the updater and the release pipeline were all
written against the platform rather than pulling something in, and that bar is
deliberate. The argument for crossing it here:

* **It is a client for someone else's interface, not a utility.** `api` carries
  the AIDL for `IShizukuService` and `IShizukuApplication`, the v11 and v13
  `attachApplication` handshake, the permission protocol, the
  `linkToDeath` plumbing, and the `UserServiceArgs` bundle keys. All of that is
  Shizuku's private wire format and Shizuku's to change. Hand-rolling it means
  re-deriving another app's internals on every Shizuku release, in a code path
  that talks to a process running as root.
* **`provider` cannot be reimplemented at all, only matched.** Shizuku delivers
  its binder by calling into a `ContentProvider` in our process with a specific
  authority, method name and `Parcelable`. There is no API — only a contract,
  and getting it subtly wrong produces an app that works on the author's phone.
* **It is small and it brings nothing with it.** A few tens of KB of Java, one
  transitive dependency (`androidx.annotation`, already on the classpath), no
  Kotlin runtime, no coroutines, no networking, no reflection into our code.
  minSdk 26 is above the API 24 that `Collection.removeIf` needs, so no library
  desugaring is required.
* **The API surface we need is not small enough to hand-roll.** Binder
  acquisition, the two-version attach handshake, permission request and result,
  binder-death notification and user-service lifecycle is most of the library.

`Shizuku.newProcess` was made private in 13.1.5 and is not used. `UserService`
is the supported path and is also strictly better here: it runs our own code
rather than parsing the text output of a shell command.

## R8

Release builds run with `isMinifyEnabled = true`, and everything in this feature
is reached **by name from another process** or by the Binder runtime. R8 sees no
call site for any of it. A stripped binder interface does not fail the build and
does not fail at install — it fails on a device, when someone presses Connect,
with nothing in the build log.

`app/proguard-rules.pro` therefore keeps `NocturneUserService` (both
constructors — Shizuku v13+ tries the `Context` one first), the generated
`INocturneService` interface with its `Stub` and `Stub$Proxy`, all of
`rikka.shizuku.**`, `rikka.sui.**` and `moe.shizuku.**`, and
`BinderContainer.CREATOR`. The project already sets `-dontobfuscate`, which
protects the names but not the classes themselves.

## Does the engine actually load over there?

This is the one thing in the feature most likely not to work, so it is worth
being precise about what is known.

**What is established.** The Shizuku starter builds the service instance off
`application.getClassLoader()`, where that `Application` came from
`createPackageContextAsUser(…, CONTEXT_INCLUDE_CODE | CONTEXT_IGNORE_SECURITY)`.
That is a real `LoadedApk` class loader with the app's native library search
path, which is what `System.loadLibrary` resolves against. The official
Shizuku-API demo does exactly this — its `UserService` has
`System.loadLibrary("hello-jni")` in a static initialiser — so JNI in a user
service is a supported, demonstrated use. `libnocturne.so` is built with
`ANDROID_STL=c++_static` and links only `libandroid`, `liblog` and `libz`, all
public system libraries, so it needs nothing else found for it.

**What could not be verified without a device.** That demo's `build.gradle` sets
`packaging { jniLibs { useLegacyPackaging true } }`, i.e.
`android:extractNativeLibs="true"`. Nocturne does not: at AGP 8.7 the default is
`false`, so `libnocturne.so` is stored uncompressed inside `base.apk` and is
loaded from `base.apk!/lib/arm64-v8a/` rather than from a real directory. That
demo line is a deliberate one in an otherwise minimal project, and it may be
there because the in-APK path does not resolve in a user-service process.

**So the load is not assumed.** `NativeBridge.ensureEngine` tries
`System.loadLibrary("nocturne")` first and, if that throws,
`System.load("<nativeLibraryDir>/libnocturne.so")` second — both inside the
class loader's permitted linker namespace. It returns a sentence instead of
throwing, the service reports it in `svc.hello`, and the debugger tab shows
`COULD NOT START` with the exact message rather than a silent dead binder.

**If the field reports that both attempts fail** with a "couldn't find
libnocturne.so" message, the fix is one line in `app/build.gradle.kts`:

```kotlin
android {
    packaging {
        jniLibs { useLegacyPackaging = true }
    }
}
```

That is not set today because it is not free: it makes the APK smaller (the
libraries are stored compressed) and the install larger (they are extracted
alongside it), and `libnocturne.so` is most of this app. Flipping it for every
user on the strength of one line in someone else's demo would be the wrong
trade; flipping it on evidence would not be.

Staging `libnocturne.so` into `/data/local/tmp` and `System.load`ing it from
there is **not** a third fallback. That path is outside the class loader's
permitted namespace and the dynamic linker refuses it.

## Things worth knowing

* **`daemon(false)`.** The privileged process dies with the app process, the
  same stance `McpService` takes with `stopWithTask`. A privileged process
  outliving the app that started it is exactly what a tool like this should not
  leave behind.
* **`version(BuildConfig.VERSION_CODE)`.** Updating Nocturne makes Shizuku
  start a fresh service process rather than keep talking to yesterday's code.
* **`tag("nocturne-dbg")`.** A stable identity, so obfuscation could never make
  the app start a second service beside the first.
* **`debuggable(false)`, even in debug builds.** The process owns a ptrace
  session; opening JDWP on it means two debuggers in one picture.
* **The uid check.** `dbgCmd` and `stageChunk` compare `Binder.getCallingUid()`
  against the app's own uid and refuse anything else. Shizuku only ever hands
  the binder to our package, but a privileged surface should not rely on that
  staying true.
* **The service is single-threaded where it matters.** The native
  `DebugSession` already routes every `ptrace` call through one dedicated worker
  thread, because Linux records the *calling thread* as the tracer. Commands
  arriving on Binder threads are safe for exactly that reason, and **no C++
  change was needed for any of this**.
* **`/data/local/tmp` is a shared directory.** Anything with shell access on the
  device can list it. Staged files are `0700` inside a `0700` directory, which
  keeps every other *app* out; it cannot keep another *shell* process out,
  because that is the same uid. Do not stage something you would not put on a
  device you have already handed adb to.
