package com.trickhook.hub

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec

/**
 * The device's author identity: an elliptic-curve P-256 key kept in the
 * AndroidKeyStore under [ALIAS]. It signs the plugins this device publishes so
 * the registry, and every other device, can prove a plugin is intact and was
 * signed by the holder of THIS key.
 *
 * Honest scope, stated wherever this is surfaced: this is authorship plus
 * integrity. It is NOT a GitHub credential, and it is NOT a judgement that a
 * script is safe to run. The script still runs only in the on-device sandbox.
 *
 * Portability: EC P-256 with SHA-256 in the AndroidKeyStore is supported on
 * every API level this app targets (minSdk 26). No StrongBox is requested, so
 * devices without a secure element still generate and sign in the TEE-backed or
 * software keystore. The key is generated lazily — only [getOrCreate], called
 * from the publish path, ever creates it; [load] and the identity screen never
 * do. Signatures are ECDSA-SHA256 in the X9.62 DER encoding that the JDK's
 * Signature emits and verifies, which is what the registry's CI checks against.
 */
object DeviceKey {
    const val ALIAS = "nocturne-author-key"
    private const val KEYSTORE = "AndroidKeyStore"
    private const val SIG_ALGO = "SHA256withECDSA"

    /** A base64 X.509 SubjectPublicKeyInfo and the hex16 fingerprint over it. */
    data class Identity(val publicKeyB64: String, val fingerprint: String)

    private fun keyStore(): KeyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    /** The identity if the key already exists, else null. Never generates one. */
    fun load(): Identity? = try {
        val pub = keyStore().getCertificate(ALIAS)?.publicKey ?: return null
        identityOf(pub)
    } catch (e: Exception) {
        null
    }

    /**
     * The identity, generating the key on first use. Call this only from the
     * publish flow — it is the single place a key is ever created.
     */
    fun getOrCreate(): Identity {
        load()?.let { return it }
        val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE)
        gen.initialize(
            KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build()
        )
        return identityOf(gen.generateKeyPair().public)
    }

    /**
     * ECDSA-SHA256 over [bytes], returned in DER encoding — exactly the bytes
     * the JDK Signature produces, which the registry then base64s into the
     * `signature` field. Assumes the key exists; the publish path calls
     * [getOrCreate] first.
     */
    fun sign(bytes: ByteArray): ByteArray {
        val key = keyStore().getKey(ALIAS, null) as PrivateKey
        val s = Signature.getInstance(SIG_ALGO)
        s.initSign(key)
        s.update(bytes)
        return s.sign()
    }

    /**
     * Verify [signatureDer] (DER ECDSA-SHA256) over [bytes] against a public key
     * supplied as base64 X.509 SPKI. Used on install: the key comes from the
     * registry, never from this device's keystore. Any decode or verify error is
     * a failed verification, not a crash.
     */
    fun verify(bytes: ByteArray, publicKeyB64: String, signatureDer: ByteArray): Boolean = try {
        val spki = Base64.decode(publicKeyB64, Base64.DEFAULT)
        val pub = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki))
        val s = Signature.getInstance(SIG_ALGO)
        s.initVerify(pub)
        s.update(bytes)
        s.verify(signatureDer)
    } catch (e: Exception) {
        false
    }

    /** The hex16 fingerprint an author key hashes to, or null if it will not decode. */
    fun fingerprintOfSpki(publicKeyB64: String): String? = try {
        fingerprintOfDer(Base64.decode(publicKeyB64, Base64.DEFAULT))
    } catch (e: Exception) {
        null
    }

    private fun identityOf(pub: PublicKey): Identity {
        val der = pub.encoded // X.509 SubjectPublicKeyInfo
        return Identity(
            publicKeyB64 = Base64.encodeToString(der, Base64.NO_WRAP),
            fingerprint = fingerprintOfDer(der)
        )
    }

    /** First 16 hex characters (8 bytes) of SHA-256 over the SPKI DER, lower-case. */
    private fun fingerprintOfDer(der: ByteArray): String {
        val h = MessageDigest.getInstance("SHA-256").digest(der)
        val sb = StringBuilder(16)
        for (i in 0 until 8) sb.append("%02x".format(h[i].toInt() and 0xFF))
        return sb.toString()
    }
}
