package com.trickhook.model

import android.content.pm.ActivityInfo
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.content.pm.ProviderInfo
import android.content.pm.ServiceInfo
import android.content.pm.Signature
import android.os.Build
import java.io.ByteArrayInputStream
import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.zip.ZipFile

/**
 * The "what am I looking at, and what does it expose" view of an app — the
 * attack-surface triage the analyst reads before diving into a library.
 *
 * It is built from two independent sources, and it degrades to whichever it
 * has. PackageManager is authoritative for identity, components (with the
 * EFFECTIVE android:exported the platform computes — not the raw manifest
 * attribute, which omits the implicit-exported-with-intent-filter rule),
 * requested permissions and signing certificates. The binary AndroidManifest,
 * decoded by [ApkAnalyzer], is the ONLY source of intent-filter deep links —
 * PackageManager does not expose intent-filters at all — so it is read
 * additively: when the manifest read fails, [deepLinksNote] says so and
 * everything PackageManager returned is still shown. Native libraries are the
 * [InstalledApps] scan, reused rather than reinvented.
 */

/** One activity, service, receiver or provider — the app's attack surface. */
data class SurfaceComponent(
    val type: String,          // activity | service | receiver | provider
    val name: String,          // fully-qualified class name
    val exported: Boolean,     // effective (PackageManager) or inferred (manifest-only)
    val permission: String?,   // android:permission guarding it, if any
    val authorities: String?,  // providers only
    val deepLinks: List<DeepLink>
)

/** One requested uses-permission, flagged if it is a well-known dangerous one. */
data class SurfacePermission(
    val name: String,
    val dangerousGroup: String?   // non-null => a platform runtime permission, and which group
)

/** One signing certificate: the identity an installed APK was signed with. */
data class SigningCert(
    val sha256: String,
    val sha1: String,
    val subject: String,
    val issuer: String,
    val notBefore: String,
    val notAfter: String,
    val serial: String
)

/** The whole triage of one app, from an installed package or an opened APK file. */
data class AttackSurface(
    val ok: Boolean,
    val source: String,           // installed | file
    val pkg: String,
    val label: String,
    val versionName: String,
    val versionCode: String,
    val minSdk: String,
    val targetSdk: String,
    val debuggable: Boolean?,
    val allowBackup: Boolean?,
    val activities: List<SurfaceComponent>,
    val services: List<SurfaceComponent>,
    val receivers: List<SurfaceComponent>,
    val providers: List<SurfaceComponent>,
    val permissions: List<SurfacePermission>,
    val customPermissions: List<CustomPermission>,
    val deepLinks: List<DeepLink>,      // every component's, flattened — the external entry points
    val signing: List<SigningCert>,
    val signingNote: String,            // why [signing] is empty, when it is
    val libScan: AppLibScan?,           // native libs per ABI, from InstalledApps
    val deepLinksNote: String,          // calm reason deep links are absent, when the manifest read failed
    val error: String                   // top-level failure, when [ok] is false
) {
    val allComponents: List<SurfaceComponent>
        get() = activities + services + receivers + providers

    val exportedCount: Int
        get() = allComponents.count { it.exported }
}

/**
 * The platform's runtime ("dangerous") permissions, mapped to the group the
 * system shows the user. Matched by exact name inside the platform's own
 * namespaces — a substring test flags a third-party permission that merely
 * contains one of these words and misses a dangerous one that does not.
 */
private val DANGEROUS_PERMISSIONS: Map<String, String> = mapOf(
    "ACCESS_FINE_LOCATION" to "location",
    "ACCESS_COARSE_LOCATION" to "location",
    "ACCESS_BACKGROUND_LOCATION" to "location",
    "ACCESS_MEDIA_LOCATION" to "location",
    "CAMERA" to "camera",
    "RECORD_AUDIO" to "microphone",
    "READ_CONTACTS" to "contacts",
    "WRITE_CONTACTS" to "contacts",
    "GET_ACCOUNTS" to "contacts",
    "READ_CALENDAR" to "calendar",
    "WRITE_CALENDAR" to "calendar",
    "SEND_SMS" to "SMS",
    "RECEIVE_SMS" to "SMS",
    "READ_SMS" to "SMS",
    "RECEIVE_MMS" to "SMS",
    "RECEIVE_WAP_PUSH" to "SMS",
    "READ_CALL_LOG" to "call log",
    "WRITE_CALL_LOG" to "call log",
    "PROCESS_OUTGOING_CALLS" to "call log",
    "READ_PHONE_STATE" to "phone",
    "READ_PHONE_NUMBERS" to "phone",
    "CALL_PHONE" to "phone",
    "ANSWER_PHONE_CALLS" to "phone",
    "ACCEPT_HANDOVER" to "phone",
    "USE_SIP" to "phone",
    "ADD_VOICEMAIL" to "phone",
    "READ_EXTERNAL_STORAGE" to "storage",
    "WRITE_EXTERNAL_STORAGE" to "storage",
    "READ_MEDIA_IMAGES" to "media",
    "READ_MEDIA_VIDEO" to "media",
    "READ_MEDIA_AUDIO" to "media",
    "READ_MEDIA_VISUAL_USER_SELECTED" to "media",
    "BODY_SENSORS" to "sensors",
    "BODY_SENSORS_BACKGROUND" to "sensors",
    "ACTIVITY_RECOGNITION" to "sensors",
    "BLUETOOTH_SCAN" to "nearby devices",
    "BLUETOOTH_CONNECT" to "nearby devices",
    "BLUETOOTH_ADVERTISE" to "nearby devices",
    "UWB_RANGING" to "nearby devices",
    "NEARBY_WIFI_DEVICES" to "nearby devices",
    "POST_NOTIFICATIONS" to "notifications"
)

private val PLATFORM_PERMISSION_PREFIXES = listOf(
    "android.permission.",
    "com.android.voicemail.permission."
)

/**
 * The dangerous-permission group for [permission], or null when it is not a
 * platform runtime permission. The single source of truth for this test; the
 * APK-tab permissions view delegates here so the two can never drift.
 */
fun dangerousPermissionGroup(permission: String): String? {
    val p = permission.trim()
    val prefix = PLATFORM_PERMISSION_PREFIXES.firstOrNull { p.startsWith(it) } ?: return null
    return DANGEROUS_PERMISSIONS[p.removePrefix(prefix)]
}

object AttackSurfaceScanner {

    /** Component + permission flags every scan asks for, plus the guarded signing flag. */
    @Suppress("DEPRECATION")
    private fun baseFlags(): Int {
        var f = PackageManager.GET_ACTIVITIES or PackageManager.GET_SERVICES or
            PackageManager.GET_RECEIVERS or PackageManager.GET_PROVIDERS or
            PackageManager.GET_PERMISSIONS
        // Signing: the certificate history lives behind GET_SIGNING_CERTIFICATES
        // on API 28+, and the deprecated GET_SIGNATURES below it. minSdk is 26,
        // so BOTH paths ship. The constants are compile-time ints, inlined, so
        // naming the newer one on an older device is harmless.
        f = f or if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
            PackageManager.GET_SIGNING_CERTIFICATES
        else
            PackageManager.GET_SIGNATURES
        return f
    }

    // ------------------------------------------------------------ entry points --

    /**
     * The attack surface of an installed package. PackageManager carries the
     * identity, components, permissions and signing; the base APK's manifest is
     * read out of applicationInfo.sourceDir for deep links; native libraries are
     * the ordinary [InstalledApps.scanNativeLibs] over the app's splits.
     */
    fun fromInstalled(
        pm: PackageManager,
        pkg: String,
        label: String,
        supportedAbis: List<String>
    ): AttackSurface {
        val pi = packageInfo(pm, pkg)
            ?: return failed("installed", pkg, label,
                "PackageManager could not resolve \"$pkg\". It may have been uninstalled.")
        val mi = pi.applicationInfo?.sourceDir?.let { parseManifestAt(it) }
        val libScan = runCatchingOrNull { InstalledApps.scanNativeLibs(pm, pkg, supportedAbis) }
        return buildFromPackageInfo(pm, pi, label, "installed", mi, libScan)
    }

    /**
     * The attack surface of an opened APK file. getPackageArchiveInfo parses the
     * same identity/components/permissions out of the archive; the manifest is
     * read from the file itself for deep links; native libraries are the
     * single-file [InstalledApps.scanApkFile]. Signing certificates are not
     * reliably exposed for an archive, so [AttackSurface.signingNote] says where
     * to see them instead. If PackageManager cannot parse the archive at all,
     * this falls back to a manifest-only surface so the read is never a dead end.
     */
    fun fromApkFile(
        pm: PackageManager,
        file: File,
        supportedAbis: List<String>
    ): AttackSurface {
        val mi = parseManifestAt(file.absolutePath)
        val libScan = runCatchingOrNull {
            InstalledApps.scanApkFile(file, supportedAbis, mi?.packageName ?: "")
        }
        val pi = archiveInfo(pm, file.absolutePath)
        // getPackageArchiveInfo does not set sourceDir, so label and any resource
        // resolution have nothing to point at; give it the file it came from.
        pi?.applicationInfo?.let { ai ->
            if (ai.sourceDir == null) ai.sourceDir = file.absolutePath
            if (ai.publicSourceDir == null) ai.publicSourceDir = file.absolutePath
        }
        return when {
            pi != null -> buildFromPackageInfo(pm, pi, mi?.appLabel ?: "", "file", mi, libScan)
            mi != null && mi.ok -> buildFromManifest(mi, "file", libScan)
            else -> failed("file", mi?.packageName ?: "", "",
                "This file has no manifest PackageManager or the AXML reader could parse.")
        }
    }

    // ------------------------------------------------------------ build (PM) --

    private fun buildFromPackageInfo(
        pm: PackageManager,
        pi: PackageInfo,
        labelHint: String,
        source: String,
        mi: ManifestInfo?,
        libScan: AppLibScan?
    ): AttackSurface {
        val ai = pi.applicationInfo
        val pkg = pi.packageName ?: mi?.packageName ?: ""
        val deepLinksByFqcn = deepLinksByFqcn(pkg, mi)

        val activities = fromActivities("activity", pi.activities, deepLinksByFqcn)
        val receivers = fromActivities("receiver", pi.receivers, deepLinksByFqcn)
        val services = fromServices(pi.services, deepLinksByFqcn)
        val providers = fromProviders(pi.providers, deepLinksByFqcn)

        val permissions = (pi.requestedPermissions?.toList() ?: mi?.permissions ?: emptyList())
            .map { SurfacePermission(it, dangerousPermissionGroup(it)) }
        val custom = customPerms(pi, mi)
        val (signing, signingNote) = extractSigning(pi, source)
        val allLinks = (activities + services + receivers + providers)
            .flatMap { it.deepLinks }.distinct()

        return AttackSurface(
            ok = true,
            source = source,
            pkg = pkg,
            label = resolveLabel(pm, ai, labelHint, mi, pkg),
            versionName = pi.versionName ?: mi?.versionName ?: "",
            versionCode = versionCodeOf(pi),
            minSdk = (ai?.minSdkVersion?.takeIf { it > 0 }?.toString()) ?: mi?.minSdk ?: "",
            targetSdk = (ai?.targetSdkVersion?.takeIf { it > 0 }?.toString()) ?: mi?.targetSdk ?: "",
            debuggable = ai?.let { (it.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0 } ?: mi?.debuggable,
            allowBackup = ai?.let { (it.flags and ApplicationInfo.FLAG_ALLOW_BACKUP) != 0 } ?: mi?.allowBackup,
            activities = activities,
            services = services,
            receivers = receivers,
            providers = providers,
            permissions = permissions,
            customPermissions = custom,
            deepLinks = allLinks,
            signing = signing,
            signingNote = signingNote,
            libScan = libScan,
            deepLinksNote = if (mi == null)
                "Deep links unavailable — AndroidManifest.xml could not be read or decoded. Everything above is from PackageManager."
            else "",
            error = ""
        )
    }

    private fun fromActivities(
        type: String, arr: Array<ActivityInfo>?, dl: Map<String, List<DeepLink>>
    ): List<SurfaceComponent> = arr?.map { c ->
        SurfaceComponent(
            type = type,
            name = c.name ?: "?",
            exported = c.exported,
            permission = c.permission?.takeIf { it.isNotEmpty() },
            authorities = null,
            deepLinks = dl[c.name] ?: emptyList()
        )
    } ?: emptyList()

    private fun fromServices(
        arr: Array<ServiceInfo>?, dl: Map<String, List<DeepLink>>
    ): List<SurfaceComponent> = arr?.map { c ->
        SurfaceComponent(
            type = "service",
            name = c.name ?: "?",
            exported = c.exported,
            permission = c.permission?.takeIf { it.isNotEmpty() },
            authorities = null,
            deepLinks = dl[c.name] ?: emptyList()
        )
    } ?: emptyList()

    private fun fromProviders(
        arr: Array<ProviderInfo>?, dl: Map<String, List<DeepLink>>
    ): List<SurfaceComponent> = arr?.map { c ->
        // A provider is guarded by read/write permissions rather than one
        // android:permission; show whichever it declares.
        val perm = c.readPermission?.takeIf { it.isNotEmpty() }
            ?: c.writePermission?.takeIf { it.isNotEmpty() }
        SurfaceComponent(
            type = "provider",
            name = c.name ?: "?",
            exported = c.exported,
            permission = perm,
            authorities = c.authority,
            deepLinks = dl[c.name] ?: emptyList()
        )
    } ?: emptyList()

    // ------------------------------------------------------ build (manifest) --

    /**
     * A surface built entirely from the decoded manifest, the fallback for a
     * file PackageManager would not parse. Exported here is the raw attribute
     * where the manifest set it, and the platform default (a component with an
     * intent-filter is exported on older targetSdk) inferred where it did not.
     */
    private fun buildFromManifest(
        mi: ManifestInfo, source: String, libScan: AppLibScan?
    ): AttackSurface {
        fun rows(list: List<ApkComponent>, type: String) = list.map { c ->
            SurfaceComponent(
                type = type,
                name = c.name,
                exported = c.exported ?: (c.deepLinks.isNotEmpty() || c.actions.isNotEmpty()),
                permission = c.permission?.takeIf { it.isNotEmpty() },
                authorities = c.authorities,
                deepLinks = c.deepLinks
            )
        }
        val activities = rows(mi.activities, "activity")
        val services = rows(mi.services, "service")
        val receivers = rows(mi.receivers, "receiver")
        val providers = rows(mi.providers, "provider")
        val allLinks = (activities + services + receivers + providers)
            .flatMap { it.deepLinks }.distinct()
        return AttackSurface(
            ok = mi.ok,
            source = source,
            pkg = mi.packageName,
            label = mi.appLabel.takeIf { it.isNotBlank() && !it.startsWith("@") } ?: mi.packageName,
            versionName = mi.versionName,
            versionCode = mi.versionCode,
            minSdk = mi.minSdk,
            targetSdk = mi.targetSdk,
            debuggable = mi.debuggable,
            allowBackup = mi.allowBackup,
            activities = activities,
            services = services,
            receivers = receivers,
            providers = providers,
            permissions = mi.permissions.map { SurfacePermission(it, dangerousPermissionGroup(it)) },
            customPermissions = mi.customPermissions,
            deepLinks = allLinks,
            signing = emptyList(),
            signingNote = "Signing certificates are read from installed apps; PackageManager does not expose them for a lone APK file here.",
            libScan = libScan,
            deepLinksNote = "",
            error = if (mi.ok) "" else mi.rawXml
        )
    }

    // ------------------------------------------------------------ deep links --

    /** Manifest deep links keyed by fully-qualified class name, to join onto PM's components. */
    private fun deepLinksByFqcn(pkg: String, mi: ManifestInfo?): Map<String, List<DeepLink>> {
        if (mi == null) return emptyMap()
        val out = HashMap<String, List<DeepLink>>()
        for (c in mi.activities + mi.services + mi.receivers + mi.providers) {
            if (c.deepLinks.isNotEmpty()) out[fqcn(pkg, c.name)] = c.deepLinks
        }
        return out
    }

    /** Resolve a manifest android:name (which may be relative) to a full class name. */
    private fun fqcn(pkg: String, name: String): String = when {
        name.isEmpty() -> name
        name.startsWith(".") -> pkg + name
        !name.contains(".") -> "$pkg.$name"
        else -> name
    }

    // --------------------------------------------------------- custom perms --

    private fun customPerms(pi: PackageInfo, mi: ManifestInfo?): List<CustomPermission> {
        val fromPm = pi.permissions?.mapNotNull { p ->
            val n = p.name ?: return@mapNotNull null
            CustomPermission(n, protectionName(p))
        } ?: emptyList()
        if (fromPm.isNotEmpty()) return fromPm
        // The manifest's raw protectionLevel is an int flag; make it readable.
        return mi?.customPermissions?.map {
            CustomPermission(it.name, prettyProtection(it.protectionLevel))
        } ?: emptyList()
    }

    /** The base protection level as an int, guarding the API 28 getProtection(). */
    @Suppress("DEPRECATION")
    private fun protectionBase(p: PermissionInfo): Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) p.protection
        else (p.protectionLevel and 0xf)

    @Suppress("DEPRECATION")
    private fun protectionName(p: PermissionInfo): String = when (protectionBase(p)) {
        PermissionInfo.PROTECTION_DANGEROUS -> "dangerous"
        PermissionInfo.PROTECTION_SIGNATURE -> "signature"
        PermissionInfo.PROTECTION_SIGNATURE_OR_SYSTEM -> "signatureOrSystem"
        else -> "normal"
    }

    private fun prettyProtection(raw: String): String {
        val n = raw.removePrefix("0x").toIntOrNull(16) ?: raw.toIntOrNull()
        if (n != null) return when (n and 0xf) {
            1 -> "dangerous"
            2 -> "signature"
            3 -> "signatureOrSystem"
            else -> "normal"
        }
        return raw.ifBlank { "normal" }
    }

    // --------------------------------------------------------------- signing --

    private fun extractSigning(pi: PackageInfo, source: String): Pair<List<SigningCert>, String> {
        val sigs = signatures(pi)
        if (sigs.isEmpty()) {
            val note = if (source == "file")
                "Signing certificates are read from an installed package; open this app from the installed-apps picker to see its signer."
            else "No signing certificate was returned for this app."
            return emptyList<SigningCert>() to note
        }
        val certs = sigs.mapNotNull { certFrom(it) }
        return certs to if (certs.isEmpty())
            "A signing block was present but could not be decoded as an X.509 certificate."
        else ""
    }

    private fun signatures(pi: PackageInfo): List<Signature> = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val si = pi.signingInfo
            when {
                si == null -> emptyList()
                si.hasMultipleSigners() -> si.apkContentsSigners?.toList() ?: emptyList()
                else -> si.signingCertificateHistory?.toList() ?: emptyList()
            }
        } else {
            legacySignatures(pi)
        }
    } catch (t: Throwable) {
        emptyList()
    }

    @Suppress("DEPRECATION")
    private fun legacySignatures(pi: PackageInfo): List<Signature> =
        pi.signatures?.toList() ?: emptyList()

    private fun certFrom(sig: Signature): SigningCert? = try {
        val raw = sig.toByteArray()
        val x = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(raw)) as X509Certificate
        SigningCert(
            // The SHA-256 of the DER certificate bytes — the fingerprint apksigner
            // and Play both report — so it can be pasted into a pin check as-is.
            sha256 = fingerprint(raw, "SHA-256"),
            sha1 = fingerprint(raw, "SHA-1"),
            subject = try { x.subjectX500Principal.name } catch (t: Throwable) { "" },
            issuer = try { x.issuerX500Principal.name } catch (t: Throwable) { "" },
            notBefore = fmtDate(x.notBefore),
            notAfter = fmtDate(x.notAfter),
            serial = try { x.serialNumber?.toString(16)?.uppercase() ?: "" } catch (t: Throwable) { "" }
        )
    } catch (t: Throwable) {
        null
    }

    private fun fingerprint(bytes: ByteArray, algo: String): String = try {
        // Mask to an unsigned int per byte: "%02X".format(aByte) sign-extends a
        // negative byte to eight hex digits, so 0xFF would print as FFFFFFFF.
        MessageDigest.getInstance(algo).digest(bytes)
            .joinToString(":") { "%02X".format(it.toInt() and 0xFF) }
    } catch (t: Throwable) {
        ""
    }

    private fun fmtDate(d: java.util.Date?): String =
        if (d == null) "" else try {
            SimpleDateFormat("yyyy-MM-dd", Locale.US).format(d)
        } catch (t: Throwable) {
            d.toString()
        }

    // ------------------------------------------------------------ PM compat --

    @Suppress("DEPRECATION")
    private fun packageInfo(pm: PackageManager, pkg: String): PackageInfo? = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
            pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(baseFlags().toLong()))
        else
            pm.getPackageInfo(pkg, baseFlags())
    } catch (t: Throwable) {
        null
    }

    @Suppress("DEPRECATION")
    private fun archiveInfo(pm: PackageManager, path: String): PackageInfo? = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
            pm.getPackageArchiveInfo(path, PackageManager.PackageInfoFlags.of(baseFlags().toLong()))
        else
            pm.getPackageArchiveInfo(path, baseFlags())
    } catch (t: Throwable) {
        null
    }

    @Suppress("DEPRECATION")
    private fun versionCodeOf(pi: PackageInfo): String =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) pi.longVersionCode.toString()
        else pi.versionCode.toString()

    private fun resolveLabel(
        pm: PackageManager, ai: ApplicationInfo?, hint: String, mi: ManifestInfo?, pkg: String
    ): String {
        if (hint.isNotBlank() && !hint.startsWith("@")) return hint
        if (ai != null) {
            val l = try { pm.getApplicationLabel(ai).toString() } catch (t: Throwable) { "" }
            if (l.isNotBlank() && l != pkg && !l.startsWith("@")) return l
        }
        val ml = mi?.appLabel
        if (!ml.isNullOrBlank() && !ml.startsWith("@")) return ml
        return pkg
    }

    // --------------------------------------------------------------- helpers --

    private fun parseManifestAt(apkPath: String): ManifestInfo? {
        val bytes = readManifestBytes(apkPath) ?: return null
        return runCatchingOrNull { ApkAnalyzer.parseManifest(bytes) }?.takeIf { it.ok }
    }

    private fun readManifestBytes(apkPath: String): ByteArray? = try {
        ZipFile(File(apkPath)).use { zf ->
            zf.getEntry("AndroidManifest.xml")?.let { e ->
                zf.getInputStream(e).use { it.readBytes() }
            }
        }
    } catch (t: Throwable) {
        null
    }

    private fun <T> runCatchingOrNull(block: () -> T): T? = try { block() } catch (t: Throwable) { null }

    private fun failed(source: String, pkg: String, label: String, error: String) = AttackSurface(
        ok = false, source = source, pkg = pkg, label = label.ifBlank { pkg },
        versionName = "", versionCode = "", minSdk = "", targetSdk = "",
        debuggable = null, allowBackup = null,
        activities = emptyList(), services = emptyList(),
        receivers = emptyList(), providers = emptyList(),
        permissions = emptyList(), customPermissions = emptyList(),
        deepLinks = emptyList(), signing = emptyList(), signingNote = "",
        libScan = null, deepLinksNote = "", error = error
    )
}
