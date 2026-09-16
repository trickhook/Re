package com.trickhook.update

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import androidx.core.content.pm.PackageInfoCompat
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Verification checks 2 and 3: what the downloaded file *is*, decided before
 * anything is allowed to happen to it.
 *
 * Check 2 is the digest of the bytes on disk. Check 3 is the certificate that
 * signed them, compared against the certificate of the Nocturne that is
 * actually running. Android enforces check 3 too, at install time — but it
 * enforces it by refusing with "App not installed", which tells the user
 * nothing at all. Deciding it here means a tampered or unrelated APK never
 * reaches the installer, and the person holding the phone gets a sentence they
 * can act on instead of a system error they cannot.
 */

private const val HEX_DIGITS = "0123456789abcdef"
private const val DIGEST_BUFFER = 64 * 1024

/** The build that is running, as the package manager sees it. */
data class InstalledBuild(
    val packageName: String,
    val versionCode: Long,
    val versionName: String
)

/**
 * Who signed a package.
 *
 * [current] is the certificate the package carries now — the value
 * `apksigner verify --print-certs` prints, and the value the release workflow
 * writes into the metadata as `apk.signerSha256`.
 *
 * [lineage] is every certificate the package may legitimately present: the
 * rotation history when there is one signer, or every co-signer when there are
 * several. Two packages are update-compatible when their lineages intersect,
 * which is how a key rotation stays installable.
 */
data class CertIdentity(
    val packageName: String,
    val lineage: Set<String>,
    val current: Set<String>,
    /** True when [current] is the well-known Android debug certificate. */
    val debugKey: Boolean
)

// ------------------------------------------------------------- check two --

/**
 * SHA-256 of a file, read back off the disk it was written to.
 *
 * Deliberately not computed while streaming the download: a digest taken from
 * the bytes in flight says nothing about what actually landed. This reads the
 * finished file.
 */
fun sha256OfFile(file: File): String {
    val md = MessageDigest.getInstance("SHA-256")
    FileInputStream(file).use { input ->
        val buf = ByteArray(DIGEST_BUFFER)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            md.update(buf, 0, n)
        }
    }
    return hex(md.digest())
}

/** Null when the file is the one the release described; a failure when it is not. */
fun verifyDigest(apk: File, rel: UpdateRelease): UpdateFailure? {
    val actual = sha256OfFile(apk)
    return if (actual.equals(rel.sha256, ignoreCase = true)) null
    else failHashMismatch(rel.sha256, actual)
}

// ----------------------------------------------------------- check three --

/**
 * Null when the downloaded APK may replace the installed app; a failure
 * naming the exact reason when it may not.
 *
 * Three ways to fail, in order of how specific the answer can be:
 *  - it is a different application (package name),
 *  - the APK is not signed by the key its own release metadata names,
 *  - the signer does not match this device's copy — and when the reason for
 *    that is the debug key on one side and the release key on the other, say
 *    so, because no retry will ever fix it.
 */
fun verifySigning(context: Context, apk: File, rel: UpdateRelease): UpdateFailure? {
    val installed = identityOfInstalled(context) ?: return failUnreadableInstalled()
    val incoming = identityOfArchive(context, apk.absolutePath) ?: return failUnreadableArchive()

    if (incoming.packageName.isNotEmpty() && incoming.packageName != installed.packageName) {
        return failWrongPackage(installed.packageName, incoming.packageName)
    }
    if (installed.lineage.isEmpty()) return failUnreadableInstalled()
    if (incoming.lineage.isEmpty()) return failUnreadableArchive()

    // The release says who signed the APK; the APK says who signed the APK.
    // If those two disagree, one of them was swapped after the other was
    // written, and neither can be trusted to describe the other.
    val claimed = rel.signerSha256
    if (claimed.isNotEmpty() && !incoming.current.contains(claimed)) {
        return failSignerDisagrees(claimed, oneOf(incoming.current))
    }

    if (installed.lineage.intersect(incoming.lineage).isNotEmpty()) return null

    if (installed.debugKey && !incoming.debugKey) return failDebugInstalledReleaseOffered()
    if (!installed.debugKey && incoming.debugKey) return failReleaseInstalledDebugOffered()
    return failSignatureMismatch(oneOf(installed.current), oneOf(incoming.current))
}

// --------------------------------------------------------------- package --

fun installedBuild(context: Context): InstalledBuild {
    val pm = context.packageManager
    return try {
        val pi = pm.getPackageInfo(context.packageName, 0)
        InstalledBuild(
            context.packageName,
            PackageInfoCompat.getLongVersionCode(pi),
            pi.versionName.orEmpty()
        )
    } catch (e: Exception) {
        InstalledBuild(context.packageName, 0L, "")
    }
}

fun identityOfInstalled(context: Context): CertIdentity? = try {
    identityOf(context.packageManager.getPackageInfo(context.packageName, signingFlags()))
} catch (e: Exception) {
    null
}

fun identityOfArchive(context: Context, path: String): CertIdentity? = try {
    identityOf(context.packageManager.getPackageArchiveInfo(path, signingFlags()))
} catch (e: Exception) {
    null
}

// ----------------------------------------------------------------- plumb --

@Suppress("DEPRECATION")
@SuppressLint("PackageManagerGetSignatures")
private fun signingFlags(): Int =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) PackageManager.GET_SIGNING_CERTIFICATES
    else PackageManager.GET_SIGNATURES

/**
 * minSdk is 26, so both eras have to be handled: `SigningInfo` only exists from
 * API 28, and below it the single `signatures` array is everything there is.
 */
@Suppress("DEPRECATION")
private fun identityOf(pi: PackageInfo?): CertIdentity? {
    if (pi == null) return null
    val pkg = pi.packageName.orEmpty()
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        val si = pi.signingInfo ?: return null
        // hasMultipleSigners() is what picks between the two arrays, and the
        // pair is not interchangeable. With several co-signers there is no
        // rotation history and apkContentsSigners is the whole answer; with one
        // signer, signingCertificateHistory is the rotation lineage with the
        // current certificate last, and an update is legitimate if it meets the
        // installed app anywhere along that chain.
        val contents: Array<Signature>? = si.apkContentsSigners
        val lineage: Array<Signature>? =
            if (si.hasMultipleSigners()) si.apkContentsSigners else si.signingCertificateHistory
        return identityFrom(pkg, contents, lineage)
    }
    val sigs: Array<Signature>? = pi.signatures
    return identityFrom(pkg, sigs, sigs)
}

private fun identityFrom(
    pkg: String,
    current: Array<Signature>?,
    lineage: Array<Signature>?
): CertIdentity? {
    val cur = digestsOf(current)
    val lin = digestsOf(lineage)
    if (cur.isEmpty() && lin.isEmpty()) return null
    val effectiveCurrent = if (cur.isNotEmpty()) cur else lin
    val effectiveLineage = if (lin.isNotEmpty()) lin else cur
    // Read off the CURRENT certificate only. A lineage that once passed through
    // a debug key would otherwise mark a perfectly ordinary release build.
    val currentSigs = if (current != null && current.isNotEmpty()) current else lineage
    return CertIdentity(pkg, effectiveLineage, effectiveCurrent, anyDebugKey(currentSigs))
}

private fun digestsOf(sigs: Array<Signature>?): Set<String> {
    if (sigs == null) return emptySet()
    val out = LinkedHashSet<String>()
    for (s in sigs) {
        // Signature.toByteArray() is the DER-encoded X.509 certificate, so this
        // is byte-for-byte the digest apksigner prints and the workflow stores
        // as apk.signerSha256.
        out.add(hex(MessageDigest.getInstance("SHA-256").digest(s.toByteArray())))
    }
    return out
}

private fun anyDebugKey(sigs: Array<Signature>?): Boolean {
    if (sigs == null) return false
    for (s in sigs) if (isDebugCertificate(s)) return true
    return false
}

/**
 * The Android debug certificate is self-signed with a fixed subject —
 * `CN=Android Debug, O=Android, C=US` — and every debug build on every machine
 * carries it. Recognising it by name is what turns "App not installed" into a
 * sentence that explains itself.
 */
private fun isDebugCertificate(sig: Signature): Boolean = try {
    val cf = CertificateFactory.getInstance("X.509")
    val cert = cf.generateCertificate(ByteArrayInputStream(sig.toByteArray())) as X509Certificate
    cert.subjectX500Principal.name.contains("CN=Android Debug", ignoreCase = true)
} catch (e: Exception) {
    false
}

private fun oneOf(digests: Set<String>): String {
    for (d in digests) return d
    return ""
}

private fun hex(bytes: ByteArray): String {
    val sb = StringBuilder(bytes.size * 2)
    for (b in bytes) {
        val v = b.toInt() and 0xFF
        sb.append(HEX_DIGITS[v ushr 4])
        sb.append(HEX_DIGITS[v and 0x0F])
    }
    return sb.toString()
}
