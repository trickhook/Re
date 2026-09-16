package com.trickhook.update

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The in-app updater's vocabulary: what a release says about itself, what can
 * go wrong, and what the sheet is showing right now.
 *
 * Nothing in this package runs unless the user asks for it. Nocturne holds
 * `android.permission.INTERNET` for exactly one purpose — reading the release
 * metadata below off GitHub and downloading the APK it describes — and no other
 * code path in the app opens a socket.
 */

/**
 * The manifest shape this updater knows. `.github/workflows/build.yml` writes
 * `"schema": 1`; a release announcing anything else is declined rather than
 * guessed at, because the one thing that must never happen is an updater
 * misreading a digest and installing an APK it did not actually check.
 */
const val UPDATE_SCHEMA: Int = 1

// ---------------------------------------------------------------- manifest --

/**
 * One published release, as described by the JSON metadata asset the release
 * workflow attaches beside the signed APK.
 *
 * Consumed fields, all from that asset:
 * ```
 * schema            1
 * versionCode       int, compared against BuildConfig.VERSION_CODE
 * versionName       "2.1.0"
 * tag               "v2.1.0"
 * prerelease        bool, shown but never used to refuse
 * minSdk            int, compared against Build.VERSION.SDK_INT
 * abis              ["arm64-v8a", "x86_64"], compared against Build.SUPPORTED_ABIS
 * apk.name          the release asset to download
 * apk.size          bytes, cross-checked against what GitHub says the asset is
 * apk.sha256        64 hex characters — verification check 2
 * apk.signerSha256  SHA-256 of the signing certificate — corroborates check 3
 * notes             release notes, shown in the sheet
 * ```
 * `apk.url` is deliberately NOT consumed. The download address is taken from
 * the `browser_download_url` GitHub itself reports for the asset named
 * [apkName], so the contents of the manifest can never redirect the download
 * somewhere the release does not live.
 */
data class UpdateRelease(
    val versionCode: Long,
    val versionName: String,
    val apkName: String,
    val apkSize: Long,
    /** Lower-case hex, 64 characters. Validated before it is stored. */
    val sha256: String,
    /** Lower-case hex of the signing certificate, or "" when the release omits it. */
    val signerSha256: String,
    val notes: String,
    val apkUrl: String,
    val tag: String,
    val prerelease: Boolean
)

// ----------------------------------------------------------------- failure --

/** What the user can do about a failure, if anything. */
enum class UpdateFix {
    /** Nothing to offer but the words. */
    NONE,

    /** Worth trying again — offline, timeout, GitHub having a bad day. */
    RETRY,

    /** Android has to be told this app may install packages. */
    GRANT_INSTALL,

    /** No update can ever be installed over this build; it has to go first. */
    UNINSTALL_FIRST
}

/**
 * A failure the user is allowed to read. [title] is one line, and is also what
 * goes to the toast channel; [detail] says what it means and what state the
 * device is in now. Neither ever carries a stack trace or a Java class name.
 */
data class UpdateFailure(
    val title: String,
    val detail: String,
    val fix: UpdateFix = UpdateFix.NONE
)

/** Thrown across the updater's own call stack; always carries a readable [failure]. */
class UpdateException(val failure: UpdateFailure) : Exception(failure.title)

// ------------------------------------------------------------------- state --

/**
 * Where the updater stands. Download progress is deliberately NOT in here: it
 * changes several times a second, and a new state object per tick would rebuild
 * the whole sheet. See `StudioViewModel.updateBytes` / `updateTotal`.
 */
sealed interface UpdateState {
    data object Idle : UpdateState
    data object Checking : UpdateState
    data class UpToDate(val versionName: String, val versionCode: Long) : UpdateState
    data class Available(val rel: UpdateRelease) : UpdateState
    data class Downloading(val rel: UpdateRelease) : UpdateState

    /** [step] is the human name of the check in flight, e.g. "SHA-256". */
    data class Verifying(val rel: UpdateRelease, val step: String) : UpdateState

    /** Both checks passed. [path] is an app-private file nothing else has touched. */
    data class Ready(val rel: UpdateRelease, val path: String) : UpdateState

    /** [rel] is kept when it is known, so the sheet can still name the version that failed. */
    data class Failed(val failure: UpdateFailure, val rel: UpdateRelease?) : UpdateState
}

// ------------------------------------------------------------------ format --

fun humanBytes(n: Long): String {
    val kb = 1024.0
    return when {
        n >= kb * kb * kb -> "%.1f GB".format(n / (kb * kb * kb))
        n >= kb * kb -> "%.1f MB".format(n / (kb * kb))
        n >= kb -> "%.1f KB".format(n / kb)
        else -> "$n B"
    }
}

/** The first 16 characters of a digest, which is as much as a person can compare. */
fun shortHash(hex: String): String = if (hex.length <= 16) hex else hex.substring(0, 16) + "…"

/** apksigner prints digests with colons on some paths and without on others. */
fun normalizeHex(s: String): String = s.filter { it.isLetterOrDigit() }.lowercase()

// --------------------------------------------------------------- failures --
// Every message below is written to be read by someone who is not us: what
// happened, what it means, and what state this device is in now.

internal fun failOffline(host: String) = UpdateFailure(
    "Could not reach $host",
    "The address did not resolve. This device looks offline, or DNS is being blocked. " +
        "Nothing else in Nocturne uses the network, so the rest of the app is unaffected.",
    UpdateFix.RETRY
)

internal fun failTimeout(host: String) = UpdateFailure(
    "$host did not answer in time",
    "The connection opened but the response never arrived — a captive or very slow network. " +
        "Nothing was downloaded.",
    UpdateFix.RETRY
)

internal fun failNetwork(what: String) = UpdateFailure(
    "The update check failed",
    "$what Nothing was downloaded and nothing on this device was changed.",
    UpdateFix.RETRY
)

internal fun failGithub(code: Int, message: String) = UpdateFailure(
    "GitHub answered $code",
    (if (message.isBlank()) "" else "$message. ") +
        "The releases service is unreachable or returned an error. That is a GitHub problem, " +
        "not a problem with the binary you have open.",
    UpdateFix.RETRY
)

/**
 * The unauthenticated REST API allows 60 requests an hour per address and
 * answers 403 with `x-ratelimit-remaining: 0` once they are gone; the reset
 * time comes back in `x-ratelimit-reset` as epoch seconds. Say it in the
 * device's own clock, because "try again later" is not an answer.
 */
internal fun failRateLimited(resetEpochSeconds: Long?): UpdateFailure {
    val whenText = if (resetEpochSeconds == null || resetEpochSeconds <= 0L) {
        "Try again in about an hour."
    } else {
        val resetMs = resetEpochSeconds * 1000L
        val mins = ((resetMs - System.currentTimeMillis() + 59_999L) / 60_000L).coerceAtLeast(1L)
        val clock = SimpleDateFormat("HH:mm", Locale.US).format(Date(resetMs))
        "The allowance comes back at $clock — about $mins minute" +
            (if (mins == 1L) "." else "s from now.")
    }
    return UpdateFailure(
        "GitHub is rate-limiting this network",
        "GitHub's release API allows 60 requests an hour from one address without an account, " +
            "and this address has spent them — often because a whole network shares it. " +
            whenText,
        UpdateFix.NONE
    )
}

internal fun failNoRelease(repo: String) = UpdateFailure(
    "There is no published release yet",
    "GitHub has no release for $repo, so there is nothing to update to. Builds from CI are " +
        "not releases; only a tagged, signed release can be installed this way.",
    UpdateFix.NONE
)

internal fun failNoManifest(asset: String, tag: String) = UpdateFailure(
    "Release $tag carries no update metadata",
    "The updater looks for an asset named $asset beside the APK, and this release has none. " +
        "Without it there is no published digest to check the download against, so nothing " +
        "is downloaded. Fetch the APK from the release page by hand instead.",
    UpdateFix.NONE
)

internal fun failManifest(problem: String) = UpdateFailure(
    "The release metadata could not be read",
    "$problem. The updater will not install an APK it cannot describe, so nothing was downloaded.",
    UpdateFix.NONE
)

internal fun failManifestField(field: String) = failManifest(
    "the metadata is missing `$field`"
)

internal fun failManifestSha(value: String) = failManifest(
    "`apk.sha256` is not 64 hex characters (it reads \"${shortHash(value)}\")"
)

internal fun failSchema(found: Int) = UpdateFailure(
    "This release speaks a newer metadata format",
    "Its update metadata announces schema $found, and this build of Nocturne only knows " +
        "schema $UPDATE_SCHEMA. Rather than guess at fields it does not recognise — and risk " +
        "checking the wrong digest — the updater declines. Install the release by hand from " +
        "the GitHub releases page.",
    UpdateFix.NONE
)

internal fun failMinSdk(need: Int, have: Int) = UpdateFailure(
    "That release needs a newer Android",
    "It requires API level $need and this device runs API $have. Nothing was downloaded.",
    UpdateFix.NONE
)

internal fun failAbi(offered: String, device: String) = UpdateFailure(
    "That release does not carry code for this device",
    "Its APK ships $offered, and this device is $device. Installing it would leave the native " +
        "engine missing. Nothing was downloaded.",
    UpdateFix.NONE
)

internal fun failMissingApkAsset(name: String, tag: String) = UpdateFailure(
    "Release $tag is missing its APK",
    "The metadata names $name, but no asset of that name is attached to the release. The " +
        "release is incomplete; nothing was downloaded.",
    UpdateFix.NONE
)

internal fun failSizeDisagrees(manifestSize: Long, assetSize: Long) = UpdateFailure(
    "The release contradicts its own metadata",
    "The metadata says the APK is ${humanBytes(manifestSize)}; GitHub says the attached asset " +
        "is ${humanBytes(assetSize)}. Two descriptions of one file disagree, so the updater " +
        "will not download it.",
    UpdateFix.NONE
)

internal fun failNotHttps(url: String) = UpdateFailure(
    "Refused a non-HTTPS address",
    "The updater was sent to $url, which is not HTTPS. Plain HTTP can be rewritten in transit " +
        "by anything between this phone and GitHub, so the transfer was abandoned.",
    UpdateFix.NONE
)

internal fun failWrite(problem: String) = UpdateFailure(
    "The download could not be saved",
    "$problem. Free some storage and try again; nothing was installed.",
    UpdateFix.RETRY
)

internal fun failTruncated(got: Long, expected: Long) = UpdateFailure(
    "The download ended early",
    "${humanBytes(got)} of ${humanBytes(expected)} arrived before the connection closed. The " +
        "partial file has been deleted.",
    UpdateFix.RETRY
)

/** Verification check 2 of 3. */
internal fun failHashMismatch(expected: String, actual: String) = UpdateFailure(
    "Rejected: this is not the file GitHub described",
    "The SHA-256 of the downloaded APK does not match the release metadata.\n" +
        "Expected  ${shortHash(expected)}\n" +
        "Got       ${shortHash(actual)}\n" +
        "The bytes that arrived are not the bytes that were published — a corrupted or " +
        "truncated transfer, a caching proxy in the way, or something altering the download. " +
        "The file has been deleted and nothing was handed to the installer.",
    UpdateFix.RETRY
)

/** Verification check 3 of 3. */
internal fun failSignatureMismatch(installed: String, incoming: String) = UpdateFailure(
    "Rejected: the APK is signed by a different key",
    "The signing certificate on the downloaded APK does not match the certificate of the " +
        "Nocturne installed on this device.\n" +
        "Installed  ${shortHash(installed)}\n" +
        "Download   ${shortHash(incoming)}\n" +
        "An APK signed by another key is a different application wearing this one's name, not " +
        "an update to it. Android would refuse the install; the updater refuses first, so the " +
        "file never reaches the installer. It has been deleted.",
    UpdateFix.NONE
)

/** Check 3, corroborated: the APK and the metadata disagree about who signed it. */
internal fun failSignerDisagrees(manifest: String, actual: String) = UpdateFailure(
    "Rejected: the release disagrees with its own APK",
    "The metadata says the APK was signed by ${shortHash(manifest)}, and the APK that arrived " +
        "is signed by ${shortHash(actual)}. One of the two was substituted after the other was " +
        "written. The file has been deleted.",
    UpdateFix.NONE
)

internal fun failWrongPackage(installed: String, incoming: String) = UpdateFailure(
    "Rejected: this APK is a different application",
    "The download declares the package $incoming, and this app is $installed. It cannot be an " +
        "update to Nocturne. The file has been deleted.",
    UpdateFix.NONE
)

internal fun failUnreadableArchive() = UpdateFailure(
    "Rejected: the download is not a readable APK",
    "Android could not parse the downloaded file as an application package, so its signing " +
        "certificate cannot be checked. The file has been deleted.",
    UpdateFix.RETRY
)

internal fun failUnreadableInstalled() = UpdateFailure(
    "Could not read this app's own signing certificate",
    "Without it there is nothing to compare the download against, and the updater will not " +
        "install an APK whose signer it has not verified. The download has been deleted.",
    UpdateFix.NONE
)

/**
 * The case that otherwise reaches the user as an unexplained "App not installed".
 *
 * A debug build is signed with the Android debug key out of ~/.android, not
 * with the project's release key. Android identifies an application by (package
 * name, signing key), so a release APK is not an update to a debug build — it
 * is a second, conflicting installation of the same package, and the platform
 * refuses it. Retrying can never change that, so the updater says so instead of
 * offering a button that cannot work.
 */
internal fun failDebugInstalledReleaseOffered() = UpdateFailure(
    "This build can never be updated in place",
    "The copy of Nocturne on this device is signed with the Android debug key — it came from a " +
        "local build or a CI debug artifact. The release is signed with the project's release " +
        "key. Android identifies an app by its package name AND its signing key, so it will " +
        "never replace one with the other, and neither will this updater.\n\n" +
        "To move onto release builds: export anything you want to keep, uninstall this build, " +
        "then install the release APK from the GitHub releases page. Uninstalling deletes the " +
        "project database along with the app.",
    UpdateFix.UNINSTALL_FIRST
)

internal fun failReleaseInstalledDebugOffered() = UpdateFailure(
    "That release is a debug build",
    "The Nocturne on this device is signed with the project's release key, and the APK this " +
        "release points at is signed with the Android debug key. Android will not replace one " +
        "with the other. That is a fault in the release, not on this device; the file has been " +
        "deleted.",
    UpdateFix.NONE
)

internal fun failInstallPermission() = UpdateFailure(
    "Android has not allowed Nocturne to install apps",
    "Since Android 8 an app needs its own permission before it may hand a package to the " +
        "installer. Open Settings, allow \"Install unknown apps\" for Nocturne, then come back " +
        "and press Install again. The verified APK is still here; nothing is downloaded twice.",
    UpdateFix.GRANT_INSTALL
)

internal fun failNoInstaller() = UpdateFailure(
    "This device has no package installer",
    "Nothing on this Android build answers a request to install a package, which usually means " +
        "a stripped or managed image. The verified APK is in Nocturne's private storage and " +
        "cannot be installed from here.",
    UpdateFix.NONE
)

internal fun failUnexpected(message: String?) = UpdateFailure(
    "The update failed",
    (message?.takeIf { it.isNotBlank() }?.plus(". ") ?: "") +
        "Nothing was installed and nothing on this device was changed.",
    UpdateFix.RETRY
)
