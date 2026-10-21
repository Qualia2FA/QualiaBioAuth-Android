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

/**
 * Seals a short secret behind the device's user authentication.
 *
 * The contract is the one the Rust `qualia-bioauth` crate documents for its
 * `PlatformSealer`: the bytes [seal] returns must be openable only by the same platform
 * key, and [unseal] must perform user verification. An implementation that keeps a copy of
 * the key in software, or that "seals" with a key it also stores in plaintext, does not
 * satisfy this contract even though the code compiles.
 *
 * Every method may prompt, and the two suspending ones may take as long as the user takes
 * to touch the sensor.
 */
interface BiometricSealer {
    /** Reports what this device can do, without prompting. */
    suspend fun availability(): Availability

    /**
     * Seals [plaintext] and returns the envelope to persist.
     *
     * @throws BiometricAuthException.Cancelled when the user dismissed the prompt.
     * @throws BiometricAuthException.Unavailable when the platform cannot authenticate.
     */
    suspend fun seal(plaintext: ByteArray): ByteArray

    /**
     * Prompts, authenticates the user, and returns the bytes [seal] was given.
     *
     * Implementations must not return bytes whose authenticity they could not establish:
     * a failed unseal is an exception, never a zero-filled buffer.
     */
    suspend fun unseal(envelope: ByteArray): ByteArray

    /** Deletes the platform key. Idempotent. */
    fun delete()
}

/** The failures a sealer reports, as cases the caller can act on. */
sealed class BiometricAuthException(message: String, cause: Throwable? = null) :
    Exception(message, cause) {
    /** The user dismissed the prompt, or it timed out. */
    class Cancelled(cause: Throwable? = null) : BiometricAuthException("the prompt was dismissed", cause)

    /** The platform cannot authenticate right now: no enrolment, or a locked-out sensor. */
    class Unavailable(reason: String, cause: Throwable? = null) : BiometricAuthException(reason, cause)

    /** This API level cannot provide the mechanism. */
    class Unsupported(reason: String) : BiometricAuthException(reason)

    /** The envelope is damaged, or it was written by another key. */
    class EnvelopeInvalid(reason: String, cause: Throwable? = null) : BiometricAuthException(reason, cause)
}
