# Release signing and cutting a release

Nocturne updates itself. The app checks the latest GitHub Release, downloads the
APK, verifies its SHA-256 and hands it to Android to install. Android will only
accept that install as an *update* if the new APK is signed with the same key as
the copy already on the device.

That one fact drives everything below.

---

## Read this before you generate anything

**If you lose this keystore, or forget its passwords, every installed copy of
Nocturne is stranded.**

Android identifies an app by its package name *and* its signing certificate. A
new keystore produces a different certificate, so an APK signed with it is, to
Android, a different application that happens to share a name. Installing it
over the old one fails with `INSTALL_FAILED_UPDATE_INCOMPATIBLE`. There is no
override, no support ticket, no recovery. Every user has to uninstall Nocturne —
losing their local data with it — and install the new one by hand. The in-app
updater cannot do that for them, which means most of them simply never update
again.

Google Play has a key-reset process for apps enrolled in Play App Signing.
Nocturne is distributed through GitHub Releases, so no such process exists here.

The keystore you are about to create is the most valuable file in this project.
Back it up before you use it.

---

## 1. Generate the keystore

Run this anywhere except inside the repository. Pick a directory you back up.

```
keytool -genkeypair -v \
  -keystore nocturne-release.jks \
  -storetype PKCS12 \
  -alias nocturne \
  -keyalg RSA -keysize 4096 \
  -sigalg SHA256withRSA \
  -validity 10950 \
  -dname "CN=Nocturne, O=Nocturne, C=US"
```

`keytool` ships with the JDK. If it is not on your PATH, it is in the `bin`
directory of your Java installation.

It will prompt you twice for a password. Choose a long random one from a
password manager and let the manager store it. Do not invent one you think you
will remember; you will need it every time you cut a release for the next thirty
years.

What the flags are for:

| Flag | Why |
|------|-----|
| `-storetype PKCS12` | The standard format. JDK 9 and later default to it anyway; naming it means you get the same file on any JDK. |
| `-keyalg RSA -keysize 4096` | RSA is what Android's APK Signature Scheme v2 and v3 expect. 4096 bits costs a few milliseconds at build time and nothing at install time. |
| `-sigalg SHA256withRSA` | SHA-1 signatures are rejected by modern Android. |
| `-validity 10950` | Thirty years. The certificate must not expire while any install is still in the field, and you cannot extend it afterwards. Google's own guidance is to outlast the app. |
| `-dname` | Skips the interactive name/organisation questions. Change it to whatever you want; it is cosmetic and visible to anyone who inspects the APK. |

With PKCS12, the store password and the key password are the same value. Set
both secrets below to it.

### Confirm it worked

```
keytool -list -v -keystore nocturne-release.jks -alias nocturne
```

Note the line `Certificate fingerprints: SHA256:` — that is your app's identity.
Every release CI publishes prints the same fingerprint into the run summary. If
it ever changes, something has gone wrong; stop and work out what before
publishing.

---

## 2. Back it up, now, before the first release

The keystore is a small binary file. Losing it is unrecoverable, so keep copies
that cannot all fail at once:

1. **Your password manager.** Most support file attachments. Store
   `nocturne-release.jks` as an attachment on the same entry as its password, so
   the file and the password can never drift apart.
2. **An encrypted archive somewhere offline** — an encrypted USB drive or disk
   image in a drawer. Offline copies survive an account compromise.
3. **A second location you control** that is not the machine you build on and is
   not this repository.

The GitHub secret is not a backup. Secrets are write-only: once set, nobody —
including you — can read the value back out.

Test a restore once. Copy the backup somewhere fresh and run the `keytool -list`
command above against it. A backup you have never restored is a guess.

---

## 3. Set the four repository secrets

Encode the keystore as a single line of base64:

```
base64 -w0 nocturne-release.jks > nocturne-release.jks.b64
```

On macOS, `base64 -w0` is not supported; use `base64 -i nocturne-release.jks | tr -d '\n'`.

Then go to **Settings > Secrets and variables > Actions > New repository secret**
and add all four:

| Secret | Value |
|--------|-------|
| `RELEASE_KEYSTORE_BASE64` | the entire contents of `nocturne-release.jks.b64` |
| `RELEASE_KEYSTORE_PASSWORD` | the store password you chose |
| `RELEASE_KEY_ALIAS` | `nocturne` (or whatever you passed to `-alias`) |
| `RELEASE_KEY_PASSWORD` | the key password — the same value, with PKCS12 |

All four are required. The build refuses to start a release if any one of them
is missing, rather than quietly producing something nobody can install.

Delete the `.b64` file afterwards — it is the keystore in another coat:

```
rm nocturne-release.jks.b64
```

Never commit the keystore. `.gitignore` covers `*.jks` and `keystore.properties`,
and the workflow re-checks that with `git check-ignore` on every release, but the
rule is worth keeping in your head too.

---

## 4. Cut a release

A release is one deliberate act: pushing a version tag. Nothing else publishes.
Pushing to `main` or to a branch builds a debug APK and stops there.

```
git tag -a v2.1.0 -m "Ghidra decompiler for MIPS and PowerPC.

- SLEIGH specifications for both architectures now ship in the APK
- Call-graph focus mode no longer loses the selection on rotate
- Fixes a crash opening PE files larger than 512 MB"

git push origin v2.1.0
```

The annotated tag's message becomes the release notes — both the "what's new"
text the app shows on the update prompt and the top of the GitHub Release page,
above the commit list GitHub generates. Write it for a user, not for yourself.

Tag format: `vMAJOR.MINOR.PATCH`, or `vMAJOR.MINOR.PATCH-rcN` with N from 1 to 8
for a release candidate. Anything else does not trigger a release at all.

A release candidate is published as a GitHub pre-release. GitHub excludes
pre-releases from "latest", so the in-app updater never offers one to an ordinary
user, while a tester who installed `v2.1.0-rc1` is still offered `v2.1.0` when it
ships.

`versionCode` is derived from the tag as
`MAJOR * 10000000 + MINOR * 10000 + PATCH * 10 + (9, or N for -rcN)`, so it rises
with the version and the same tag always produces the same number.

### What the release contains

Three assets, every time:

| Asset | What the updater does with it |
|-------|-------------------------------|
| `Nocturne-<version>.apk` | the signed APK it installs |
| `nocturne-update.json` | version numbers, the APK's size and SHA-256, and the notes — read first, on a tap |
| `Nocturne-<version>.apk.sha256` | the same digest in `sha256sum -c` format, for checking a download by hand |

### Undoing one

Delete the release **and** the tag before anyone's phone checks for updates:

```
gh release delete v2.1.0 --cleanup-tag
```

To hold every publish for a manual approval instead, add yourself as a required
reviewer under **Settings > Environments > release**. The workflow already
targets that environment; with no protection rules it simply passes through.

---

## 5. Building a signed release locally

You do not need this to ship — CI does it — but if you want a signed APK on your
own machine, create `app/keystore.properties`, which is gitignored:

```
storeFile=/absolute/path/to/nocturne-release.jks
storePassword=...
keyAlias=nocturne
keyPassword=...
```

Then `./gradlew assembleRelease`.

Two things to know:

- Without that file, `assembleRelease` still succeeds and produces
  `app-release-unsigned.apk`. Unsigned APKs cannot be installed. CI passes
  `NOCTURNE_REQUIRE_SIGNING=true` so that the same situation fails loudly there
  instead.
- `java.util.Properties` treats `\` as an escape character, so a password
  containing a backslash has to be written `\\` in that file. CI sidesteps this
  entirely by passing the passwords through the environment
  (`NOCTURNE_KEYSTORE_PASSWORD` and friends) and never writing them to disk.

### Debug builds and release builds cannot coexist

Both use the application ID `com.trickhook`, but they are signed with different
keys. If you already have a debug build on the device, installing a release over
it fails with `INSTALL_FAILED_UPDATE_INCOMPATIBLE`. Uninstall first:

```
adb uninstall com.trickhook
```

This applies to your users too, once: anyone running a debug APK from the CI
artifacts has to uninstall it before they can move to a release. From then on the
in-app updater handles it.

---

## 6. If the worst happens

**Keystore lost, no backup.** There is no way to update existing installs.
Generate a new keystore, bump the major version, and say plainly in the release
notes that this version must be installed manually after uninstalling the old
one. Then set up the backups in section 2.

**Keystore leaked.** Anyone holding it can sign an APK that Android accepts as a
Nocturne update. Generate a new keystore immediately and treat it as the case
above. Releases are signed with APK Signature Scheme v3, which supports proof-of-
rotation: if you still have the old key, a v3 rotation lets new releases keep
updating existing installs under the new key. That path is worth researching
before you fall back to asking everyone to reinstall.

**Passwords lost but the file survives.** The same as losing the keystore. The
file is useless without them.
