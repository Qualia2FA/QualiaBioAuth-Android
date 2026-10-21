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
 * What this device can do, asked before offering the authenticated path.
 *
 * Mirrors the Rust crate's `Availability` so that a caller can map one onto the other
 * without deciding anything a second time. The distinction matters: [Unavailable] means
 * the mechanism exists but this device or user cannot use it right now (no enrolment, a
 * key invalidated by a new fingerprint), while [Unsupported] means this build cannot do it
 * at all (Android below API 28). The caller keeps the password path in both cases, but the
 * explanation it shows the user differs.
 */
sealed interface Availability {
    /** The device can seal and unseal. */
    data class Available(
        /** Whether the key lives in hardware (TEE or StrongBox) rather than in software. */
        val hardwareBacked: Boolean,
    ) : Availability

    /** The mechanism exists, but this device or user cannot use it right now. */
    data class Unavailable(val reason: String) : Availability

    /** This build cannot provide the mechanism on this API level at all. */
    data class Unsupported(val reason: String) : Availability
}
