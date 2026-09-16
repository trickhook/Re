<div align="center">

<img src="assets/banner.svg" width="100%" alt="Nocturne — Mobile-first Interactive Disassembler & Decompiler Framework"/>

<img src="assets/app-icon.png" width="128" alt="Nocturne app icon"/>

# 🌙 Nocturne

### Mobile-first Interactive Disassembler & Decompiler Framework

*A fork of [Sako RE Studio](https://github.com/Maxamedxasa/SakoREStudio) by **Maxamed Xasan Muse** — rebranded, rethemed, and extended to decode every
architecture Capstone supports. Original work and MIT licence: see [Author](#-qoraaga--author).*

**IDA Pro & Ghidra — gacanta ku jira / in your pocket**

[![Release](https://img.shields.io/github/v/release/trickhook/Re?style=for-the-badge&color=FB1B69&label=Download)](https://github.com/trickhook/Re/releases/latest)
[![Platform](https://img.shields.io/badge/Android-8.0%2B-3DDC84?style=for-the-badge&logo=android&logoColor=white)](https://github.com/trickhook/Re/releases/latest)
[![Arch](https://img.shields.io/badge/Decodes-ARM64_·_ARM/Thumb_·_x86_·_MIPS_·_PPC_·_SPARC_·_SysZ_·_m68k-C792EA?style=for-the-badge)](#-known-limitations)
[![Made In Somalia](https://img.shields.io/badge/%F0%9F%87%B8%F0%9F%87%B4_MADE_IN-SOMALIA-4189DD?style=for-the-badge)](#-qoraaga--author)
[![Author](https://img.shields.io/badge/Author-Maxamed_Xasan_Muse-34D399?style=for-the-badge)](#-qoraaga--author)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![Build](https://img.shields.io/github/actions/workflow/status/trickhook/Re/build.yml?style=for-the-badge&label=Build%20APK&logo=githubactions&logoColor=white)](https://github.com/trickhook/Re/actions/workflows/build.yml)

**[⬇️ DOWNLOAD APK](https://github.com/trickhook/Re/actions/workflows/build.yml)** · [🇸🇴 Soomaali](#soomaali) · [🇬🇧 English](#english)

<img src="assets/demo.gif" width="300" alt="Nocturne demo — disassembly, call graph, decompiler"/>

</div>

---

<a name="soomaali"></a>
## 🇸🇴 SOOMAALI

### 🧠 Waa maxay Nocturne?

**Nocturne** waa qalab buuxa oo *reverse engineering* ah oo mobile-ka lagu shaqeeyo — disassembler, decompiler, call graph, debugger, APK analyzer iyo nidaam plugins oo dhan ayaa isku hal app ku dhex jira. Hadalka uga gaabkan: **waa IDA Pro ama Ghidra, laakiin telefoonkaada gacanta ku jira.** Engine-ka waa C++17 (NDK) oo ku shaqeeya Capstone 4.0.2, UI-guna waa Kotlin Jetpack Compose oo casri ah. Waxaa lagu falanqayn karaa **APK · ELF · PE · DEX** — **ARM64 · ARM/Thumb · x86 · x86-64 · MIPS · PowerPC · SPARC · SystemZ · m68k** (little- iyo big-endian labadaba). Wax walba app-ka dhexdiisa ayay ka dhacaan (app-ku ma laha ogolaansho internet).

App-kan waxaa si buuxda ah u sameeyay horumariye Soomaaliyeed — waa qalabkii ugu horreeyay ee noocaan ah oo ka soo saarma Soomaaliya 🇸🇴

### ✨ Awoodaha (Features)

| # | Feature | Waxa ay samayso |
|---|---------|-----------------|
| 1 | 🗄️ **Kaydinka Mashruuca (SQLite)** | Rename kasta, comment, bookmark iyo note si toos ah ayay SQLite u kaydisaan — app-ka wuu xirmay markale, waxba ma lumiyaan |
| 2 | 🔍 **Falanqayn Xeelad Leh** | Helitaanka functions-ka si otomaatig ah, call graph dhab ah (PLT/GOT/IAT resolution), xrefs, C++ demangler (Itanium + MSVC), iyo auto-comments (string refs, APIs khatar ah ⚠) |
| 3 | ⚙️ **Decompiler (IR dhab ah)** | ASM → **IR** → pseudo-C: expression trees, propagation, DSE, `while` loops (back-edges), `if/else`, call arguments, iyo kala-duw uur variables (`u64 a0`) |
| 4 | 🕸️ **Graph View** | CFG isdhexgal ah: jiid (drag) nodes-ka, zoom, midabada block-yada (green=entry, red=exit, amber=branch), raadin iyo **minimap** |
| 5 | 🐞 **Debugger Dhab Ah** | ptrace session: **Spawn / Attach PID**, software breakpoints (BRK / 0xCC), registers (akhris/qorid), memory read/write, stack view, thread list |
| 6 | 📦 **APK Analyzer** | Manifest (AXML binary parser): package, version, **permissions** (kuwo khatar ah ayaa ⚠ lagu calaamadaynayaa), activities/services/receivers + intent-filters, DEX classes, native libs, resources wata image preview |
| 7 | 🧩 **Plugin System (NocturneScript)** | Luuqad programming oo app-ka ku dhex jirta (variables, if/while/for, functions) + host API 20+ oo function ah. 4 plugin ayaa la soo shubay |
| 8 | 📱 **UI Casri Ah** | 13 tab, **command palette (Ctrl+K)**, search everywhere (Ctrl+F), goto address (Ctrl+G), shortcuts buuxa (F1 = caawimo) |

### 📲 Sida Loo Rakibo

1. APK-ga ka soo qaado [**Actions → Build APK → Artifacts**](https://github.com/trickhook/Re/actions/workflows/build.yml) (`Nocturne-debug-apk`) ama [**Releases**](https://github.com/trickhook/Re/releases/latest)
2. Fur APK-ga → hadduu browser-ku ama file manager-ku dhib ku qado → ogol **"Install unknown apps"**
3. Rakib → fur → **diyaar!** (Android 8.0+ · arm64-v8a & x86_64 · ma u baahna root — debugger-keliya ayaa root u baahan)

### 🚀 Sida Loo Isticmaalo — Hagaha Buuxa

**1 · Fur file**
App-ka fur → ku dhufo **📂** (ama `Ctrl+K` → "Open file") → dooro `.apk`, `.so`, `.dex` ama `.exe`. Tusaale diyaar ah waxaad ku haysataa `app/samples/` (test.so, test_arm64.so, test.dex, test.exe) — ku soo dhaji telefoonka, markaas ku fur app-ka.

**2 · Falanqayn otomaatig**
Engine-ku wuu falanqaynayaa keligiis: functions, strings, imports/exports, xrefs iyo call graph. Console-ka (tab-ka u dambeeya) waxaad aragtaan iyada: `OK · 7,012 functions · 14,203 xrefs`.

**3 · Assembly (disassembly)**
Tab-ka **Assembly** → dooro function → waxaad aragtaan disassembly wata auto-comments (tusmo string-yada, call targets, APIs khatar ah ⚠). **Long-press** on line → rename function / comment / bookmark — wax walba SQLite ayay ku kaydaan.

**4 · Pseudo-C (decompiler)**
Tab-ka **Pseudo-C** → engine-ku ASM-ka ayuu u rogayaa IR, kadibna pseudo-C qaab la akhriyi karo (`while`, `if/else`, call args...). Waxaad aragtaan tirakoobka pipeline-ga: IR nodes, DSE, loops.

**5 · Graph (CFG)**
Tab-ka **Graph** → jaantuska function-ka: nodes-ka waad jiidi kartaa, pinch zoom, midabyada block-yada wax kasta sheegaan, **minimap**-ka geeska hoose ayaa degdeg u dhaqaaqinaya.

**6 · CallGraph**
Tab-ka **CallGraph** → "Whole binary" ama "This function" → tree-ka calls / called-by; imports-ka waa amber.

**7 · APK**
Tab-ka **APK** → Manifest (laga furay AXML-ka binary-ga ah), Permissions (kuwo khatar ah ⚠), Components + intent-filters, DEX classes, Native libs (**tap = extract + falanqayn**), Resources (**tap image = preview**).

**8 · Debugger** *(root ama debuggable device)*
Tab-ka **Debugger** → **Spawn** (tusaale: `/system/bin/toybox sleep 30`) → **BP @ function** → markuu breakpoint-ku gaaro: registers, memory, stack, threads → **Continue**. Ama **Attach PID** process jira.

**9 · Plugins**
Tab-ka **Plugins** → 10 plugin ayaa diyaar (`security-auditor`, `crypto-finder`, `anti-debug-scanner`, `jni-mapper`, `xref-hotspots`, `attack-surface`, `string-triage`, `arm-analyzer`, `dex-helper`, `string-hunter`) → **Run** → effects-ka (rename/comment) si toos ah DB-ga u geliyaan.

**10 · Kaydi**
`Ctrl+S` → mashruuca SQLite-ga ayaa la kaydiyaa → drawer-ka **RECENT PROJECTS** ka fur markale.

### 🧩 NocturneScript — Luuqada Plugins-ka

```js
## Tusaale: baarista APIs-ka khatar ah
n  = count_functions()
ni = count_imports()
log("functions:", n, "· imports:", ni)

risky = 0
for i in 0..ni-1 {
    imp = import_at(i)
    if classify(imp.name) == "dangerous" {
        log("[!] UNSAFE:", imp.name)
        risky = risky + 1
    }
}

for i in 0..n-1 {
    f = func_at(i)
    if f.size > 2048 {
        comment(f.addr, "LARGE function — audit manually")
    }
}
```

**Host API:** `log()` · `count_functions()` · `func_at(i)` · `func_by_name()` · `count_strings()` · `string_at(i)` · `count_imports()` · `import_at(i)` · `demangle()` · `classify()` · `count_xrefs_to()` · `xref_to_at()` · `rename()` · `comment()` · `bookmark()` · `hex()` · `strlen()` · `charat()` · `str()`
**Luuqada:** numbers/strings/bools/objects · `if/else` · `while` · `for i in a..b { }` · `fun f(x) { return x }`

### ⌨️ Keyboard Shortcuts

| Key | Waxay samayso |
|-----|----------------|
| `Ctrl+K` | Command palette |
| `Ctrl+F` | Search everywhere (functions + strings + comments + bookmarks) |
| `Ctrl+G` | U dhaqaaq address (goto) |
| `Ctrl+O` | Fur file |
| `Ctrl+S` | Kaydi mashruuca |
| `Ctrl+T` | Beddel dark/light theme |
| `Ctrl+1..9` | Tab u dhaqaaq |
| `F1` | Caawimo buuxda |

---

<a name="english"></a>
## 🇬🇧 ENGLISH

### 🧠 What is Nocturne?

**Nocturne** is a complete *reverse engineering* suite that runs entirely on your phone — an interactive disassembler, an IR-based decompiler, a call-graph explorer, a real ptrace debugger, an APK analyzer and a plugin scripting system, all inside one app. In the shortest possible terms: **it is IDA Pro / Ghidra, rebuilt mobile-first.** The engine is C++17 (Android NDK) powered by Capstone 4.0.2, the UI is modern Kotlin Jetpack Compose. It analyzes **APK · ELF · PE · DEX** binaries for **ARM64, ARM/Thumb, x86, x86-64, MIPS, PowerPC, SPARC and m68k** — little- and big-endian alike — plus SystemZ, which disassembles but does not decompile, because Ghidra ships no z/Architecture processor module and so there is no specification to compile — and every byte of it stays on the device: the app declares no network permission at all.

Built end-to-end by a Somali developer — the first mobile reverse-engineering studio of its kind out of Somalia 🇸🇴

### ✨ Features

| # | Feature | What it does |
|---|---------|--------------|
| 1 | 🗄️ **Project Database (SQLite)** | Every rename, comment, bookmark and note persists per-project — close the app, reopen, nothing is lost |
| 2 | 🔍 **Deep Analysis Engine** | Automatic function discovery, real call graph (PLT/GOT/IAT resolution), xrefs, C++ demangler (Itanium + MSVC), auto-comments (string refs, dangerous APIs ⚠) |
| 3 | ⚙️ **IR Decompiler** | ASM → **IR** → pseudo-C: expression trees, propagation, dead-store elimination, `while` loops from back-edges, `if/else` structuring, call arguments, typed declarations (`u64 a0`) |
| 4 | 🕸️ **Interactive Graph View** | CFG canvas: drag nodes, zoom, color-coded blocks (green=entry, red=exit, amber=branch), search + **minimap** |
| 5 | 🐞 **Real Debugger** | ptrace session: **Spawn / Attach PID**, software breakpoints (BRK / 0xCC with auto-rewind), register read/write, memory read/write, stack view, thread list |
| 6 | 📦 **APK Analyzer** | Binary AXML manifest parser: package/version/SDK, **permissions** (dangerous ones flagged ⚠), components + intent-filters, DEX classes, native libs, resources with image preview |
| 7 | 🧩 **Plugin System (NocturneScript)** | An embedded scripting language (variables, if/while/for, functions) + a 20+-function host API. 4 plugins bundled |
| 8 | 📱 **Modern UI** | 13 tabs, **command palette (Ctrl+K)**, search everywhere (Ctrl+F), goto address (Ctrl+G), full keyboard shortcuts (F1 = help) |

### 📲 Install

1. Grab the APK from [**Actions → Build APK → Artifacts**](https://github.com/trickhook/Re/actions/workflows/build.yml) (`Nocturne-debug-apk`), or from [**Releases**](https://github.com/trickhook/Re/releases/latest)
2. Open the APK → if prompted, allow **"Install unknown apps"**
3. Install → open → **done!** (Android 8.0+ · arm64-v8a & x86_64 · no root required — only the debugger needs root/debuggable)

### 🚀 Quick Start

1. **Open a binary** — tap **📂** (or `Ctrl+K` → "Open file") and pick `.apk` / `.so` / `.dex` / `.exe`. Ready-made samples live in `app/samples/` (test.so, test_arm64.so, test.dex, test.exe) — push them to the phone and open them.
2. **Automatic analysis** — the engine discovers functions, strings, imports/exports, xrefs and the call graph by itself. The **Console** tab narrates everything: `OK · 7,012 functions · 14,203 xrefs`.
3. **Assembly** — pick a function: Capstone disassembly with auto-comments (string references, call targets, dangerous APIs ⚠). **Long-press** any line → rename / comment / bookmark (persisted to SQLite).
4. **Pseudo-C** — the decompiler tab: ASM → IR → readable C-like code with loops, branches and call arguments, plus pipeline stats (IR nodes, DSE, loops).
5. **Graph** — the function's control-flow graph: drag nodes, pinch-zoom, color-coded blocks, minimap for fast navigation.
6. **CallGraph** — whole-binary tree or per-function callers/callees; imports highlighted in amber.
7. **APK** — decoded manifest, permissions (dangerous flagged ⚠), components with intent-filters, DEX classes, native libs (**tap = extract + analyze**), resources (**tap image = preview**).
8. **Debugger** *(root/debuggable device)* — **Spawn** (e.g. `/system/bin/toybox sleep 30`) → **BP @ function** → on hit inspect registers/memory/stack/threads → **Continue**. Or **Attach** to a running PID.
9. **Plugins** — run the 10 bundled NocturneScript plugins (`security-auditor`, `arm-analyzer`, `dex-helper`, `string-hunter`); effects are applied straight into the project database.
10. **Save** — `Ctrl+S` persists the SQLite project; reopen later from **RECENT PROJECTS** in the drawer.

### 🧩 NocturneScript — the Plugin Language

```js
## Example: hunt dangerous APIs
n  = count_functions()
ni = count_imports()
log("functions:", n, "· imports:", ni)

risky = 0
for i in 0..ni-1 {
    imp = import_at(i)
    if classify(imp.name) == "dangerous" {
        log("[!] UNSAFE:", imp.name)
        risky = risky + 1
    }
}

for i in 0..n-1 {
    f = func_at(i)
    if f.size > 2048 {
        comment(f.addr, "LARGE function — audit manually")
    }
}
```

**Host API:** `log()` · `count_functions()` · `func_at(i)` · `func_by_name()` · `count_strings()` · `string_at(i)` · `count_imports()` · `import_at(i)` · `demangle()` · `classify()` · `count_xrefs_to()` · `xref_to_at()` · `rename()` · `comment()` · `bookmark()` · `hex()` · `strlen()` · `charat()` · `str()`
**Language:** numbers/strings/bools/objects · `if/else` · `while` · `for i in a..b { }` · `fun f(x) { return x }`

### 🛠️ Build from Source

**Requirements:** Android Studio (Ladybug+) · NDK 27.2.12479018 · CMake 3.22.1 · JDK 17 (bundled with Studio)

```bash
git clone https://github.com/trickhook/Re.git
# Android Studio → File → Open → select the cloned folder
# wait for Gradle sync → Run ▶  (first sync downloads Gradle 8.10.2 + deps)
```

**Command line:**
```bash
./gradlew assembleDebug          # debug APK — works out of the box
```

**Build + install on a connected device in one step:**
```bash
./scripts/install-apk.sh                 # builds, installs over adb, launches the app
./scripts/install-apk.sh -s SERIAL       # when several devices are attached
./scripts/install-apk.sh --skip-build    # reinstall the APK you already built
```
Requires USB debugging and `adb` on your PATH. The debug APK is signed with the
standard Android debug key, so it installs with no keystore setup at all.

**Don't want to build locally? Download the APK from CI.**
Every push runs [`.github/workflows/build.yml`](.github/workflows/build.yml),
which provisions the pinned NDK/CMake, builds the native engine for both ABIs
and uploads the APK:

1. Open the [**Build APK**](https://github.com/trickhook/Re/actions/workflows/build.yml)
   workflow (or press **Run workflow** to start one by hand)
2. Pick the run → **Artifacts** → `Nocturne-debug-apk`
3. Unzip, then `adb install -r Nocturne-*-debug.apk` — or copy the APK to the
   phone and tap it (allow *Install unknown apps* when prompted)

The run summary lists each APK with its size and SHA-256. Pushing a `v*` tag
additionally attaches the APKs to a GitHub Release.

CI builds the **release** APK too, but only when release signing secrets are
configured on the repository — `RELEASE_KEYSTORE_BASE64` (the `.jks`,
base64-encoded), `RELEASE_KEYSTORE_PASSWORD`, `RELEASE_KEY_ALIAS` and
`RELEASE_KEY_PASSWORD`. Without them an unsigned release APK cannot be
installed, so CI skips it and ships the debug APK only.

**Release signing (optional):** create `app/keystore.properties` (gitignored):
```properties
storeFile=nocturne-release.jks
storePassword=your_password
keyAlias=your_alias
keyPassword=your_password
```
Generate a keystore with:
```bash
keytool -genkeypair -v -keystore app/nocturne-release.jks -alias your_alias \
  -keyalg RSA -keysize 2048 -validity 10000
```
Without this file, release builds simply produce an unsigned APK — debug builds always work.

**Project layout:**
```
app/src/main/
├── cpp/capstone/            vendored Capstone 4.0.2
├── cpp/sako/                C++17 engine: loaders (ELF/PE/DEX), disassembler,
│                            IR decompiler, deep analysis, call graph,
│                            debug session, NocturneScript interpreter, JSON API
├── cpp/sako_jni.cpp         JNI bridge
├── assets/plugins/          bundled NocturneScript plugins (4)
├── java/com/sakore/studio/
│   ├── data/ProjectDb.kt    SQLite project database
│   ├── engine/NativeBridge.kt
│   ├── model/ApkAnalyzer.kt binary AXML parser
│   ├── ui/                  Compose UI (13 tabs, graph, palette, debugger…)
│   └── vm/StudioViewModel.kt
└── samples/                 test.so · test_arm64.so · test.dex · test.exe
```

### ⚠️ Known Limitations

- **Debugger** needs a rooted or `ro.debuggable=1` device (SELinux may deny ptrace for system binaries). Breakpoints are software-based; no hardware watchpoints yet.
- **Decompiler** is a real IR pipeline, but not Hex-Rays: no switch/jump-table recovery and no exception handling. The IR lifter targets ARM64 and x86-64; other architectures disassemble fully but decompile heuristically.
- **RISC-V, SuperH and IA-64** ELFs are identified and parsed, but Capstone 4.0.2 has no decoder for them, so no disassembly is produced.
- **DEX bytecode disassembly** is not included (Capstone has no Dalvik backend) — classes, methods, strings and the invoke-based call graph are fully available.
- **resources.arsc** names are not decoded yet (entries listed + image previews work).

---

<a name="qoraaga"></a>
## 👤 Qoraaga / Author

<div align="center">

### **Maxamed Xasan Muse** 🇸🇴

*Horumariye Soomaaliyeed — Somali Developer*

> *"Nocturne waa app-ka ugu horreeya ee noocaan ah oo Soomaaliya laga soo saaro.
> Cilmiga reverse engineering-ka waa inuu gaaraa qof kasta — telefoonka kaliya."*

**GitHub:** [github.com/Maxamedxasa](https://github.com/Maxamedxasa)

🇸🇴 **MADE IN SOMALIA — WITH PRIDE**

</div>

## 📄 License

[MIT](LICENSE) © 2026 Maxamed Xasan Muse

## ⭐ Support

Hadduu app-ku anfacay / If this project helped you, please **star ⭐ the repo** and share it!

