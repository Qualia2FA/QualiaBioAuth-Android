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

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The envelope reader is the one part of the library that parses bytes from a file, so it
 * is the part a damaged or hostile blob reaches first.
 *
 * Every case here is a length or a version, not a cryptographic check: the AEAD tag is
 * verified by the platform, and these tests are about rejecting nonsense before that.
 */
class EnvelopeTest {
    private val iv = ByteArray(Envelope.IV_LEN) { it.toByte() }
    private val ciphertext = ByteArray(32) { (it + 100).toByte() }

    /** A sealed blob survives the trip through the envelope. */
    @Test
    fun a_sealed_blob_roundtrips() {
        val envelope = Envelope.encode(iv, ciphertext)
        val (decodedIv, decodedCiphertext) = Envelope.decode(envelope)
        assertContentEquals(iv, decodedIv)
        assertContentEquals(ciphertext, decodedCiphertext)
    }

    /** The header carries the version and the IV length. */
    @Test
    fun the_header_states_the_version_and_the_iv_length() {
        val envelope = Envelope.encode(iv, ciphertext)
        assertEquals(Envelope.VERSION, envelope[0])
        assertEquals(Envelope.IV_LEN, envelope[1].toInt())
        assertEquals(Envelope.HEADER_LEN + Envelope.IV_LEN + ciphertext.size, envelope.size)
    }

    /** An unknown version is refused rather than read under this layout. */
    @Test
    fun an_unknown_version_is_refused() {
        val envelope = Envelope.encode(iv, ciphertext)
        envelope[0] = 2
        assertFailsWith<BiometricAuthException.EnvelopeInvalid> { Envelope.decode(envelope) }
    }

    /** A different IV length is refused: the layout depends on the cipher's nonce size. */
    @Test
    fun a_different_iv_length_is_refused() {
        val envelope = Envelope.encode(iv, ciphertext)
        envelope[1] = 16
        assertFailsWith<BiometricAuthException.EnvelopeInvalid> { Envelope.decode(envelope) }
    }

    /** Truncation is refused, and the length field alone cannot make a short buffer valid. */
    @Test
    fun a_truncated_envelope_is_refused() {
        val envelope = Envelope.encode(iv, ciphertext)
        for (length in 0 until Envelope.HEADER_LEN + Envelope.IV_LEN + 16) {
            val truncated = envelope.copyOf(length)
            assertFailsWith<BiometricAuthException.EnvelopeInvalid>("length $length") {
                Envelope.decode(truncated)
            }
        }
    }

    /** A buffer with no room for a GCM tag cannot be a sealed secret. */
    @Test
    fun an_envelope_without_room_for_a_tag_is_refused() {
        val tooShort = ByteArray(Envelope.HEADER_LEN + Envelope.IV_LEN + 15)
        tooShort[0] = Envelope.VERSION
        tooShort[1] = Envelope.IV_LEN.toByte()
        assertFailsWith<BiometricAuthException.EnvelopeInvalid> { Envelope.decode(tooShort) }
    }

    /** Encoding is deterministic, which is what makes the format testable at all. */
    @Test
    fun encoding_is_deterministic() {
        assertTrue(Envelope.encode(iv, ciphertext).contentEquals(Envelope.encode(iv, ciphertext)))
    }
}
