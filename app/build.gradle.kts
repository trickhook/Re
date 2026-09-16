import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

/** An environment variable, or null when it is unset or blank. */
fun env(name: String): String? = System.getenv(name)?.takeIf { it.isNotBlank() }

// ---- Release signing -------------------------------------------------------
// Two ways in, and only two.
//
//   Local build   app/keystore.properties (gitignored):
//                     storeFile=nocturne-release.jks
//                     storePassword=...
//                     keyAlias=...
//                     keyPassword=...
//
//   CI            NOCTURNE_KEYSTORE_FILE, NOCTURNE_KEYSTORE_PASSWORD,
//                 NOCTURNE_KEY_ALIAS and NOCTURNE_KEY_PASSWORD in the
//                 environment. CI decodes the keystore to a file and passes the
//                 passwords through the environment only: nothing writes them
//                 to disk, so no stray file can leak them, and a password
//                 containing a backslash cannot be mangled by the .properties
//                 escape rules (java.util.Properties treats \ as an escape).
//
// With neither, `assembleRelease` still runs and produces an *unsigned* APK.
// That is fine for a local smoke test and useless for distribution, so CI sets
// NOCTURNE_REQUIRE_SIGNING=true on the release build: a release that has lost
// its signing material then fails loudly instead of quietly shipping something
// nobody can install. See docs/RELEASE-SIGNING.md.
val keystoreProps = Properties()
val keystorePropsFile = file("keystore.properties")
val signingFromEnv = env("NOCTURNE_KEYSTORE_FILE") != null
val hasReleaseSigning = signingFromEnv || keystorePropsFile.exists()
if (!signingFromEnv && keystorePropsFile.exists()) {
    keystorePropsFile.inputStream().use { keystoreProps.load(it) }
}
if (env("NOCTURNE_REQUIRE_SIGNING") == "true" && !hasReleaseSigning) {
    throw GradleException(
        "NOCTURNE_REQUIRE_SIGNING=true but no signing material was found. " +
            "Set NOCTURNE_KEYSTORE_FILE/_KEYSTORE_PASSWORD/_KEY_ALIAS/_KEY_PASSWORD, " +
            "or create app/keystore.properties. Refusing to build an unsigned release."
    )
}

/** A signing value that must be present once signing is switched on at all. */
fun requiredSigningEnv(name: String): String = env(name)
    ?: throw GradleException("$name is unset or blank, but NOCTURNE_KEYSTORE_FILE is set.")

// ---- Versioning ------------------------------------------------------------
// A release is one pushed tag: vMAJOR.MINOR.PATCH, or vMAJOR.MINOR.PATCH-rcN
// for a pre-release. CI passes the tag through NOCTURNE_VERSION_NAME and every
// number below is derived from it, so the tag is the only thing a human has to
// get right. Any other build — local, PR, branch CI — falls back to
// baseVersionName and is never published.
//
//   versionCode = MAJOR * 10_000_000 + MINOR * 10_000 + PATCH * 10 + qualifier
//   qualifier   = 9 for a final release, N for -rcN (N in 1..8)
//
// The in-app updater compares this integer against BuildConfig.VERSION_CODE, so
// it must be (a) strictly increasing with the version and (b) a pure function of
// the tag. Deriving it from the tag rather than from a run number or a commit
// count means the same tag rebuilt a year later produces the same number: a
// re-run can never hand a device a "newer" build of older code, and it can never
// produce a *lower* number for the same input either. The -rcN qualifier sorts a
// pre-release below its own final, so a tester on 2.1.0-rc1 is still offered
// 2.1.0.
//
// Ranges: major <= 200, minor <= 999, patch <= 999 — the largest representable
// code is 2_009_999_999, inside Int.MAX_VALUE, and no field can carry into the
// next one.
val baseVersionName = "2.0.3"

val resolvedVersionName: String =
    (env("NOCTURNE_VERSION_NAME") ?: baseVersionName).trim().removePrefix("v")

val resolvedVersionCode: Int = run {
    val m = Regex("""(\d+)\.(\d+)\.(\d+)(?:-rc(\d+))?""").matchEntire(resolvedVersionName)
        ?: throw GradleException(
            "Version '$resolvedVersionName' is not MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH-rcN. " +
                "Tag releases as vMAJOR.MINOR.PATCH, for example v2.1.0."
        )
    val major = m.groupValues[1].toInt()
    val minor = m.groupValues[2].toInt()
    val patch = m.groupValues[3].toInt()
    val rc = m.groupValues[4].takeIf { it.isNotEmpty() }?.toInt()
    if (major > 200) throw GradleException("Major version $major is out of range (0..200).")
    if (minor > 999) throw GradleException("Minor version $minor is out of range (0..999).")
    if (patch > 999) throw GradleException("Patch version $patch is out of range (0..999).")
    if (rc != null && rc !in 1..8) throw GradleException("Release candidate $rc is out of range (1..8).")
    major * 10_000_000 + minor * 10_000 + patch * 10 + (rc ?: 9)
}

android {
    namespace = "com.trickhook"
    compileSdk = 35
    ndkVersion = "27.2.12479018"

    defaultConfig {
        applicationId = "com.trickhook"
        minSdk = 26
        targetSdk = 35
        versionCode = resolvedVersionCode
        versionName = resolvedVersionName

        // The release side of the auto-update contract, so the updater does not
        // have to hard-code where releases live or what the metadata asset is
        // called. Both are fixed by .github/workflows/build.yml.
        buildConfigField("String", "UPDATE_REPO", "\"trickhook/Re\"")
        buildConfigField("String", "UPDATE_MANIFEST_ASSET", "\"nocturne-update.json\"")

        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
        externalNativeBuild {
            cmake {
                arguments += listOf("-DANDROID_STL=c++_static")
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                if (signingFromEnv) {
                    storeFile = file(requiredSigningEnv("NOCTURNE_KEYSTORE_FILE"))
                    storePassword = requiredSigningEnv("NOCTURNE_KEYSTORE_PASSWORD")
                    keyAlias = requiredSigningEnv("NOCTURNE_KEY_ALIAS")
                    keyPassword = requiredSigningEnv("NOCTURNE_KEY_PASSWORD")
                } else {
                    storeFile = file(keystoreProps.getProperty("storeFile"))
                    storePassword = keystoreProps.getProperty("storePassword")
                    keyAlias = keystoreProps.getProperty("keyAlias")
                    keyPassword = keystoreProps.getProperty("keyPassword")
                }
                // minSdk is 26. APK Signature Scheme v2 has been mandatory since
                // API 24, so the v1 JAR signature buys nothing; v3 is what makes
                // signing-key rotation possible later without orphaning installs.
                enableV1Signing = false
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        release {
            // R8 shrinks the Compose runtime and material-icons-extended, which
            // is most of the dex. Obfuscation is switched off in
            // proguard-rules.pro: the source is public, so renaming buys nothing,
            // and it is the usual cause of a release build that works everywhere
            // except on a user's phone. Resource shrinking stays off for the same
            // reason — the app's resources are small next to the native payload.
            isMinifyEnabled = true
            isShrinkResources = false
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
            }
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
        // AGP 8 generates BuildConfig only when this is on. The updater reads
        // BuildConfig.VERSION_CODE and BuildConfig.VERSION_NAME.
        buildConfig = true
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.material.icons.extended)
    debugImplementation(libs.androidx.ui.tooling)
}
