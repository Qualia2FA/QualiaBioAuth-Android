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
 * The bytes a sealed secret is stored as.
 *
 * `version(1) || ivLength(1) || iv || ciphertext`. The format belongs to this library
 * because only this library reads it; a caller persists the bytes and hands them back.
 *
 * The length checks are here rather than at the call site because an envelope arrives from
 * a file, and a file is attacker-controlled input: a length field that claims more bytes
 * than the buffer holds must be rejected before anything indexes into it.
 */
internal object Envelope {
    /** Current format version. A future layout takes a new number. */
    const val VERSION: Byte = 1

    /** AES-GCM nonce length, fixed by the cipher. */
    const val IV_LEN: Int = 12

    /** Bytes before the ciphertext: version and IV length. */
    const val HEADER_LEN: Int = 2

    /** Builds an envelope around [ciphertext] and its [iv]. */
    fun encode(iv: ByteArray, ciphertext: ByteArray): ByteArray {
        require(iv.size == IV_LEN) { "the IV must be $IV_LEN bytes, was ${iv.size}" }
        return ByteArray(HEADER_LEN + IV_LEN + ciphertext.size).also { out ->
            out[0] = VERSION
            out[1] = IV_LEN.toByte()
            iv.copyInto(out, HEADER_LEN)
            ciphertext.copyInto(out, HEADER_LEN + IV_LEN)
        }
    }

    /** The IV and ciphertext inside [envelope], or an exception if it is not one. */
    fun decode(envelope: ByteArray): Pair<ByteArray, ByteArray> {
        if (envelope.size < HEADER_LEN + IV_LEN + 16) {
            throw BiometricAuthException.EnvelopeInvalid("the envelope is too short")
        }
        if (envelope[0] != VERSION) {
            throw BiometricAuthException.EnvelopeInvalid(
                "unsupported envelope version ${envelope[0]}",
            )
        }
        val ivLength = envelope[1].toInt() and 0xFF
        if (ivLength != IV_LEN) {
            throw BiometricAuthException.EnvelopeInvalid("unsupported IV length $ivLength")
        }
        if (envelope.size < HEADER_LEN + ivLength) {
            throw BiometricAuthException.EnvelopeInvalid("the envelope is truncated")
        }
        val iv = envelope.copyOfRange(HEADER_LEN, HEADER_LEN + ivLength)
        val ciphertext = envelope.copyOfRange(HEADER_LEN + ivLength, envelope.size)
        return iv to ciphertext
    }
}
