# qualia-bioauth-android

中文版见 [README.md](README.md)。

The Android half of [`qualia-bioauth`](https://github.com/Qualia2FA/QualiaBioAuth): it seals
a 32-byte key behind the device's own user authentication, using the Android Keystore and
`BiometricPrompt`.

The Rust crate owns the blob format and the error taxonomy; this library owns the platform
calls. Neither knows anything about Qualia2FA.

## Usage

```kotlin
val sealer = KeystoreBiometricSealer(activity)

when (val available = sealer.availability()) {
    is Availability.Available -> { /* offer the biometric path */ }
    is Availability.Unavailable -> { /* mechanism exists, this user cannot use it */ }
    is Availability.Unsupported -> { /* API level too low; password only */ }
}

// Seal: prompts once, returns the bytes to persist.
val envelope = sealer.seal(masterKey)

// Unseal: prompts once, returns the same key or throws.
val restored = sealer.unseal(envelope)

// Turning the path off deletes the platform key; the envelope becomes dead.
sealer.delete()
```

The library never sees the key material that protects the envelope: the Keystore key is
created with `setUserAuthenticationRequired(true)`, so the platform itself refuses to use it
until the user has authenticated.

## What it guarantees, and what it does not

- **Guaranteed**: the envelope cannot be opened without a fresh user authentication on this
  device; a new biometric enrolment invalidates the key, so the envelope stops opening
  instead of silently accepting the new finger.
- **Not guaranteed**: protection against an attacker running code as this user while the
  vault is unlocked. No biometric scheme provides that.
- The library does **not** fall back to a software key. If the platform cannot authenticate,
  `availability()` says so and the caller keeps its password path.

## Requirements

- Android 26+; the biometric path itself needs 28 or newer and reports `Unsupported` below
  that.
- A screen lock and at least one enrolled biometric.
- `FragmentActivity`: `BiometricPrompt` is its own window, so it needs an Activity to attach
  to. Construct the sealer per screen rather than holding it for the process lifetime.

## Integrating

```kotlin
dependencies {
    implementation("com.qiushui1012.lib:qualia-bioauth-android:0.1.0")
}
```

## License

LGPL-3.0-or-later; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
