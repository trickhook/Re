package com.trickhook.model

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import java.io.File
import java.util.zip.ZipFile

/**
 * Reading a native library straight out of an INSTALLED app, without importing
 * an APK and without reinstalling anything.
 *
 * A modern app is a set of split APKs — a base plus per-config splits and
 * asset packs — so the .so you want is buried in one of several files under
 * /data/app. PackageManager hands back every one of those APK paths for any
 * installed package, and those files are world-readable, so with the
 * QUERY_ALL_PACKAGES visibility the app already declares (for the debugger's
 * attach picker) they can be enumerated, opened as plain ZIPs and read. No
 * root, no reinstall.
 *
 * This only READS the app's own shipped bytes. Patching a live app is a
 * separate thing done at runtime by the Frida generator or the ptrace
 * debugger; nothing here repackages or re-signs.
 */

/** One installed application, resolved from PackageManager. */
data class InstalledApp(
    val pkg: String,
    val label: String,
    val versionName: String,
    val isSystem: Boolean
)

/**
 * One native library entry found inside one split APK of an installed app.
 *
 * [libName] is the .so basename (e.g. libnative-lib.so); [abi] is the lib
 * subdirectory it sits under (e.g. arm64-v8a); [splitName] is the APK file's
 * basename (base.apk, or a config split like split_config.arm64_v8a.apk);
 * [splitPath] is that APK's absolute path; [entryName] is the ZIP entry path
 * inside the split (lib then abi then libName).
 */
data class AppNativeLib(
    val pkg: String,
    val libName: String,
    val abi: String,
    val splitName: String,
    val splitPath: String,
    val entryName: String,
    val size: Long
)

/**
 * The outcome of scanning one app's split APKs for native libraries.
 *
 * [ok] is false only when not even the APK paths could be resolved or opened.
 * [note] carries the honest reason there are no [libs]: the APKs were
 * unreadable, the app is pure DEX with no bundled native code, or its libraries
 * live in an asset pack this feature cannot read. An empty list is never
 * presented as an answer without one of those sentences beside it.
 */
data class AppLibScan(
    val pkg: String,
    val ok: Boolean,
    val primaryAbi: String,
    val apkCount: Int,
    val readableApkCount: Int,
    val libs: List<AppNativeLib>,
    val note: String
)

object InstalledApps {

    /**
     * Every installed package, resolved to a human label the same way the
     * debugger's process picker does — getApplicationLabel over the package's
     * ApplicationInfo, falling back to the package id when the label cannot be
     * read. User-installed apps sort ahead of system apps, then by label.
     *
     * getInstalledPackages carries both the ApplicationInfo and the version in
     * one call, so no per-app round trip is needed. QUERY_ALL_PACKAGES (already
     * declared) is what makes this return more than the app's own package on
     * API 30+.
     */
    fun list(pm: PackageManager): List<InstalledApp> {
        val pkgs = try {
            pm.getInstalledPackages(0)
        } catch (t: Throwable) {
            emptyList()
        }
        val out = ArrayList<InstalledApp>(pkgs.size)
        for (pi in pkgs) {
            val ai = pi.applicationInfo ?: continue
            val label = try {
                pm.getApplicationLabel(ai).toString()
            } catch (t: Throwable) {
                pi.packageName
            }
            val isSystem = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0 ||
                (ai.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
            out.add(
                InstalledApp(
                    pkg = pi.packageName,
                    label = label.ifBlank { pi.packageName },
                    versionName = pi.versionName ?: "",
                    isSystem = isSystem
                )
            )
        }
        out.sortWith(compareBy({ it.isSystem }, { it.label.lowercase() }, { it.pkg }))
        return out
    }

    /**
     * Resolve one package's base and split APK paths and read every native
     * library entry out of them.
     *
     * The paths are applicationInfo.sourceDir (the base) plus
     * applicationInfo.splitSourceDirs (the config and feature splits, which may
     * be null). Each is opened as an ordinary ZIP — the same ZipFile walk the
     * APK panel already does when it opens a picked APK — and every entry under
     * lib whose name ends in .so is collected, remembering which split and
     * which ABI it came from.
     *
     * [supportedAbis] is Build.SUPPORTED_ABIS; its first element is the device's
     * primary ABI, which the caller prefers when presenting the results.
     */
    fun scanNativeLibs(
        pm: PackageManager,
        pkg: String,
        supportedAbis: List<String>
    ): AppLibScan {
        val primaryAbi = supportedAbis.firstOrNull() ?: ""
        val ai: ApplicationInfo = try {
            pm.getApplicationInfo(pkg, 0)
        } catch (t: Throwable) {
            return AppLibScan(
                pkg, ok = false, primaryAbi = primaryAbi,
                apkCount = 0, readableApkCount = 0, libs = emptyList(),
                note = "PackageManager could not resolve this app: " +
                    (t.message ?: "not found") + "."
            )
        }

        // base first, then the splits, de-duplicated by path but keyed by the
        // APK's file name so the same split is never scanned twice.
        val apkPaths = LinkedHashMap<String, String>()
        ai.sourceDir?.let { apkPaths[File(it).name] = it }
        ai.splitSourceDirs?.forEach { sp ->
            if (sp != null) apkPaths[File(sp).name] = sp
        }
        if (apkPaths.isEmpty()) {
            return AppLibScan(
                pkg, ok = false, primaryAbi = primaryAbi,
                apkCount = 0, readableApkCount = 0, libs = emptyList(),
                note = "PackageManager reported no APK paths for this app."
            )
        }

        val libs = ArrayList<AppNativeLib>()
        var readable = 0
        for ((splitName, path) in apkPaths) {
            val f = File(path)
            if (!f.canRead()) continue
            try {
                ZipFile(f).use { zf ->
                    readable++
                    zf.entries().asSequence()
                        .filter { !it.isDirectory }
                        .forEach { e ->
                            val name = e.name
                            if (!name.startsWith("lib/") || !name.endsWith(".so")) return@forEach
                            // lib / <abi> / <name>.so — exactly three components.
                            val parts = name.split('/')
                            if (parts.size != 3) return@forEach
                            libs.add(
                                AppNativeLib(
                                    pkg = pkg,
                                    libName = parts[2],
                                    abi = parts[1],
                                    splitName = splitName,
                                    splitPath = path,
                                    entryName = name,
                                    size = e.size
                                )
                            )
                        }
                }
            } catch (t: Throwable) {
                // A split that will not open as a ZIP is skipped; it simply does
                // not contribute libraries and is not counted as readable.
            }
        }

        val note = when {
            readable == 0 ->
                "None of this app's APK files could be read from here. On a " +
                    "hardened device those files may not be world-readable."
            libs.isEmpty() ->
                "This app ships no extractable .so inside its APKs. Its native " +
                    "code may be delivered in an asset pack this feature cannot " +
                    "read, or the app is all DEX with no bundled native library."
            else -> ""
        }
        return AppLibScan(
            pkg = pkg,
            ok = readable > 0,
            primaryAbi = primaryAbi,
            apkCount = apkPaths.size,
            readableApkCount = readable,
            libs = libs,
            note = note
        )
    }
}
