package com.trickhook.update

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.core.content.FileProvider
import java.io.File

/**
 * Where the download lives, and how it is handed over.
 *
 * ## Why ACTION_INSTALL_PACKAGE and not the PackageInstaller session API
 *
 * Both need `REQUEST_INSTALL_PACKAGES` and both show the user the same system
 * confirmation, so the choice is not about what the user sees. It is about what
 * gets installed:
 *
 *  - With `ACTION_INSTALL_PACKAGE` the installer opens **the file this app
 *    verified**. The bytes whose SHA-256 was checked and whose signing
 *    certificate was read are the bytes the installer parses. Nothing is copied
 *    in between.
 *  - A `PackageInstaller` session installs a *copy* — the app streams the APK
 *    into a session and the platform installs the session's contents. The two
 *    are the same in practice, but the thing that was verified and the thing
 *    that is installed are no longer literally the same object, and on a path
 *    whose entire job is "do not install what you did not check", that
 *    distinction is worth keeping.
 *  - The session API also needs an exported-looking `BroadcastReceiver` and a
 *    `PendingIntent` to report its result. That is more security-relevant
 *    surface, in the one place in this app where a mistake hands someone else's
 *    code to the system installer.
 *
 * `ACTION_INSTALL_PACKAGE` is deprecated as of API 29 but works on every level
 * this app supports (26 to 35). What it costs is progress reporting, which is
 * no loss: the system installer draws its own. `EXTRA_RETURN_RESULT` still
 * gives back a result code, which is enough to tell "you dismissed it" from
 * "it went through".
 *
 * The APK is handed over as a `content://` URI from a [FileProvider], because a
 * `file://` URI throws `FileUriExposedException` on API 24 and up, and because
 * app-private storage is not readable by the installer any other way.
 */

/** Must match `android:authorities` on the provider in AndroidManifest.xml. */
private const val PROVIDER_SUFFIX = ".updates"

/** Must match `res/xml/update_file_paths.xml`. */
const val UPDATE_DIR = "updates"

/**
 * A fixed local name. The release names its own asset, and a name that arrived
 * over the network is never allowed to become a path on this device.
 */
const val UPDATE_FILE = "pending-update.apk"

private const val PREFS = "nocturne_updates"
private const val KEY_ON_LAUNCH = "check_on_launch"

// ---------------------------------------------------------------- storage --

fun updateApkFile(context: Context): File = File(File(context.filesDir, UPDATE_DIR), UPDATE_FILE)

/**
 * An empty app-private file to download into, with anything left over from a
 * previous attempt removed first. There is exactly one of these at a time.
 */
fun freshUpdateApk(context: Context): File {
    val dir = File(context.filesDir, UPDATE_DIR)
    if (!dir.isDirectory && !dir.mkdirs()) {
        throw UpdateException(failWrite("Nocturne's private update folder could not be created"))
    }
    val file = File(dir, UPDATE_FILE)
    if (file.exists() && !file.delete()) {
        throw UpdateException(failWrite("the previous download could not be removed"))
    }
    return file
}

/** Blocking. Call from Dispatchers.IO. */
fun deleteUpdateApk(context: Context) {
    val file = updateApkFile(context)
    if (file.exists()) file.delete()
}

// ------------------------------------------------------------ preference --

/**
 * Off unless the user turned it on. A reverse-engineering tool that contacts a
 * server on a timer is doing the one thing its users came here to avoid, so
 * there is no schedule, no background work and no first-run default — a check
 * happens when someone asks for it, or on launch only after they have said so.
 */
fun updateCheckOnLaunch(context: Context): Boolean =
    context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(KEY_ON_LAUNCH, false)

fun storeUpdateCheckOnLaunch(context: Context, on: Boolean) {
    context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        .edit()
        .putBoolean(KEY_ON_LAUNCH, on)
        .apply()
}

// ------------------------------------------------------------- hand-over --

/**
 * Since API 26 this is per-app, not a global toggle, and it is the difference
 * between a working Install button and an unexplained silent no-op.
 */
fun canInstallPackages(context: Context): Boolean =
    context.packageManager.canRequestPackageInstalls()

@Suppress("DEPRECATION")
fun installIntentFor(context: Context, apk: File): Intent {
    val uri = FileProvider.getUriForFile(context, context.packageName + PROVIDER_SUFFIX, apk)
    return Intent(Intent.ACTION_INSTALL_PACKAGE).apply {
        setDataAndType(uri, "application/vnd.android.package-archive")
        // The installer runs in another process and has no standing access to
        // Nocturne's private storage; this grant is what lets it read the one
        // file, for as long as the intent lives.
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        putExtra(Intent.EXTRA_RETURN_RESULT, true)
        putExtra(Intent.EXTRA_INSTALLER_PACKAGE_NAME, context.packageName)
    }
}

/**
 * Send the user to the screen that grants this app the right to install
 * packages. Three attempts, narrowing to broader screens, because the per-app
 * settings activity is missing on some manufacturer builds and a dead button is
 * worse than a slightly wrong screen. False means nothing on this device
 * answered at all.
 */
fun openUnknownSourcesSettings(context: Context): Boolean {
    val perApp = Intent(
        Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
        Uri.parse("package:" + context.packageName)
    )
    if (startSettings(context, perApp)) return true
    if (startSettings(context, Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES))) return true
    return startSettings(context, Intent(Settings.ACTION_SECURITY_SETTINGS))
}

private fun startSettings(context: Context, intent: Intent): Boolean = try {
    context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    true
} catch (e: ActivityNotFoundException) {
    false
} catch (e: SecurityException) {
    false
}
