// Copyright (C) 2026 Qualia2FA contributors
//
// This library is free software; you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation; either version 3 of the License, or (at your option) any
// later version.
//
// This library is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
// details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this library; if not, see <https://www.gnu.org/licenses/>.

package com.qiushui1012.qualia.bioauth

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import java.security.UnrecoverableKeyException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine

/**
 * A [BiometricSealer] backed by the Android Keystore and `BiometricPrompt`.
 *
 * The key is generated with `setUserAuthenticationRequired(true)`, so the platform refuses
 * to initialise a cipher with it until the user has authenticated. That refusal is the
 * whole mechanism: this class never sees the key, and the ciphertext cannot be opened on a
 * device where the user cannot authenticate.
 *
 * [activity] is the `FragmentActivity` the prompt is attached to; `BiometricPrompt`
 * requires one because the prompt is its own window with its own lifecycle. The sealer
 * holds it for the duration of the call, not forever: a `FragmentActivity` captured by a
 * long-lived object outlives its own screen, so callers are expected to construct this
 * class per screen.
 */
class KeystoreBiometricSealer(
    private val activity: FragmentActivity,
    private val alias: String = DEFAULT_ALIAS,
    private val promptInfo: PromptText = PromptText(),
) : BiometricSealer {

    /** The texts the system prompt shows. */
    data class PromptText(
        val title: String = "Unlock Qualia2FA",
        val subtitle: String = "Confirm it is you",
        val cancel: String = "Cancel",
    )

    override suspend fun availability(): Availability {
        if (Build.VERSION.SDK_INT < MIN_API) {
            return Availability.Unsupported(
                "Android ${Build.VERSION.RELEASE} cannot require biometric authentication " +
                    "for a key; API 28 or newer is needed",
            )
        }
        if (!activity.packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT) &&
            !activity.packageManager.hasSystemFeature(PackageManager.FEATURE_FACE) &&
            !activity.packageManager.hasSystemFeature(PackageManager.FEATURE_IRIS)
        ) {
            return Availability.Unavailable("this device has no biometric sensor")
        }
        val readable = BiometricManager.from(activity).canAuthenticate(BIOMETRIC_STRONG)
        if (readable != BiometricManager.BIOMETRIC_SUCCESS) {
            return Availability.Unavailable(describe(readable))
        }
        val keyguard = activity.getSystemService(KeyguardManager::class.java)
        if (keyguard?.isDeviceSecure != true) {
            return Availability.Unavailable("the device has no screen lock")
        }
        return Availability.Available(hardwareBacked = isHardwareBacked())
    }

    override suspend fun seal(plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key(createIfMissing = true))
        val authorized = authenticate(cipher)
        val ciphertext = authorized.doFinal(plaintext)
        return Envelope.encode(authorized.iv, ciphertext)
    }

    override suspend fun unseal(envelope: ByteArray): ByteArray {
        val (iv, ciphertext) = Envelope.decode(envelope)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        try {
            cipher.init(Cipher.DECRYPT_MODE, key(createIfMissing = false), GCMParameterSpec(TAG_BITS, iv))
        } catch (error: KeyPermanentlyInvalidatedException) {
            // A new fingerprint was enrolled, which the key spec forbids. The blob is dead
            // by design; the password path is the way in.
            throw BiometricAuthException.Unavailable(
                "the biometric enrolment changed, so the stored key can no longer be used",
                error,
            )
        } catch (error: UnrecoverableKeyException) {
            throw BiometricAuthException.Unavailable("the stored key is gone", error)
        }
        val authorized = authenticate(cipher)
        return try {
            authorized.doFinal(ciphertext)
        } catch (error: javax.crypto.AEADBadTagException) {
            throw BiometricAuthException.EnvelopeInvalid(
                "the envelope did not authenticate",
                error,
            )
        }
    }

    override fun delete() {
        val store = KeyStore.getInstance(PROVIDER).apply { load(null) }
        if (store.containsAlias(alias)) {
            store.deleteEntry(alias)
        }
    }

    /**
     * Runs the prompt around [cipher] and returns it once the platform has authorised that
     * exact cipher object.
     *
     * The cipher must be the one the user authenticated: `BiometricPrompt` hands back the
     * same `CryptoObject`, and using a freshly initialised cipher instead would throw
     * `UserNotAuthenticatedException` on the first `doFinal`.
     */
    private suspend fun authenticate(cipher: Cipher): Cipher =
        suspendCancellableCoroutine { continuation ->
            val prompt = BiometricPrompt(
                activity,
                androidx.core.content.ContextCompat.getMainExecutor(activity),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        val authorized = result.cryptoObject?.cipher
                        if (authorized == null) {
                            continuation.resumeWithException(
                                BiometricAuthException.Unavailable("the platform returned no cipher"),
                            )
                        } else {
                            continuation.resume(authorized)
                        }
                    }

                    override fun onAuthenticationError(code: Int, message: CharSequence) {
                        continuation.resumeWithException(
                            if (code == BiometricPrompt.ERROR_USER_CANCELED ||
                                code == BiometricPrompt.ERROR_CANCELED ||
                                code == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                                code == BiometricPrompt.ERROR_TIMEOUT
                            ) {
                                BiometricAuthException.Cancelled()
                            } else {
                                BiometricAuthException.Unavailable("prompt error $code: $message")
                            },
                        )
                    }

                    // A failed attempt is not the end: the prompt stays up and the user
                    // may try another finger, so nothing is resumed here.
                    override fun onAuthenticationFailed() = Unit
                },
            )
            continuation.invokeOnCancellation { prompt.cancelAuthentication() }
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(promptInfo.title)
                .setSubtitle(promptInfo.subtitle)
                .setNegativeButtonText(promptInfo.cancel)
                .setAllowedAuthenticators(BIOMETRIC_STRONG)
                .setConfirmationRequired(false)
                .build()
            prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
        }

    /** Returns the key, generating it when [createIfMissing] and it is absent. */
    private fun key(createIfMissing: Boolean): SecretKey {
        val store = KeyStore.getInstance(PROVIDER).apply { load(null) }
        val existing = store.getKey(alias, null) as? SecretKey
        if (existing != null) {
            return existing
        }
        if (!createIfMissing) {
            throw BiometricAuthException.Unavailable("no key is stored under $alias")
        }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(KEY_BITS)
            // The point of the whole class: the platform will not use this key until the
            // user has authenticated.
            .setUserAuthenticationRequired(true)
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    // A fresh authentication per use; no reuse window.
                    setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                } else {
                    @Suppress("DEPRECATION")
                    setUserAuthenticationValidityDurationSeconds(-1)
                }
            }
            // A new enrolment invalidates the key, which is the safe direction: the blob
            // stops opening rather than a new finger silently gaining access.
            .setInvalidatedByBiometricEnrollment(true)
            // GCM IVs must come from the platform, never from the caller.
            .setRandomizedEncryptionRequired(true)
            .build()
        generator.init(spec)
        return generator.generateKey()
    }

    /** Whether the key sits in a TEE or StrongBox rather than in software. */
    private fun isHardwareBacked(): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            try {
                val store = KeyStore.getInstance(PROVIDER).apply { load(null) }
                val key = store.getKey(alias, null) as? SecretKey ?: return false
                val factory = javax.crypto.SecretKeyFactory.getInstance(key.algorithm, PROVIDER)
                val info = factory.getKeySpec(
                    key,
                    android.security.keystore.KeyInfo::class.java,
                ) as android.security.keystore.KeyInfo
                info.securityLevel != android.security.keystore.KeyProperties.SECURITY_LEVEL_SOFTWARE
            } catch (_: Exception) {
                // Without a key there is nothing to report yet; the honest answer is "not
                // known to be hardware", and the caller shows the software wording.
                false
            }
        } else {
            false
        }

    /** Turns a `BiometricManager` code into something a user can act on. */
    private fun describe(code: Int): String =
        when (code) {
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "this device has no biometric hardware"
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "the biometric sensor is unavailable"
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "no fingerprint or face is enrolled"
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED ->
                "a security update is required before biometrics can be used"
            BiometricManager.BIOMETRIC_STATUS_UNKNOWN -> "the biometric status is unknown"
            else -> "biometric authentication is not available ($code)"
        }

    companion object {
        /** Default Keystore alias. One alias per application is enough: the blob is the key. */
        const val DEFAULT_ALIAS: String = "qualia-bioauth"

        /** The first API level whose Keystore can require biometric authentication per use. */
        const val MIN_API: Int = Build.VERSION_CODES.P

        private const val PROVIDER = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val TAG_BITS = 128
        private const val KEY_BITS = 256
    }
}
