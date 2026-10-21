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

plugins {
    alias(libs.plugins.androidLibrary)
    alias(libs.plugins.kotlinAndroid)
    `maven-publish`
    signing
}

group = "com.qiushui1012.lib"
version = "0.1.0"

android {
    namespace = "com.qiushui1012.qualia.bioauth"
    // AGP 8.7 tops out at compileSdk 35, and 35 is what the API level used here needs.
    compileSdk = 35

    defaultConfig {
        // 26 because the caller (Qualia2FA) supports it; the biometric path itself needs
        // 28 and reports Unsupported below that, rather than pretending to work.
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // The published artifact is a single AAR; a variant-specific one would force the
    // consumer to match flavours for no benefit.
    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }

    testOptions {
        unitTests.isIncludeAndroidResources = true
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    // BiometricPrompt, and the FragmentActivity it has to be attached to.
    api("androidx.biometric:biometric:1.1.0")
    api("androidx.activity:activity:1.9.3")
    // `ContextCompat.getMainExecutor` and `FragmentActivity`, both reached from the prompt.
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation(kotlin("test"))
    testImplementation("org.robolectric:robolectric:4.14.1")
}

publishing {
    // A local staging directory: the CI bundles whatever lands here and uploads that bundle
    // to the Central Portal, so no publishing plugin has to be pinned.
    repositories {
        maven {
            name = "staging"
            url = uri(layout.buildDirectory.dir("staging"))
        }
    }
    publications {
        create<MavenPublication>("release") {
            afterEvaluate { from(components["release"]) }
            pom {
                name.set("qualia-bioauth-android")
                description.set(
                    "Android Keystore and BiometricPrompt half of qualia-bioauth: " +
                        "seals a 32-byte key behind the device's user authentication.",
                )
                url.set("https://github.com/Qualia2FA/QualiaBioAuth-Android")
                licenses {
                    license {
                        name.set("LGPL-3.0-or-later")
                        url.set("https://www.gnu.org/licenses/lgpl-3.0.html")
                    }
                }
                developers {
                    developer {
                        id.set("qiushui1012")
                        name.set("Qualia2FA contributors")
                        email.set("dev@qiushui1012.com")
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/Qualia2FA/QualiaBioAuth-Android.git")
                    url.set("https://github.com/Qualia2FA/QualiaBioAuth-Android")
                }
            }
        }
    }
}

// Signing is configured only when the CI provides a key: a plain local build must not
// require a GPG secret just to compile the library.
val signingKey: String? = System.getenv("MAVEN_CENTRAL_SIGNING_KEY")
val signingPassword: String? = System.getenv("MAVEN_CENTRAL_SIGNING_PASSWORD")

signing {
    if (signingKey != null && signingPassword != null) {
        useInMemoryPgpKeys(signingKey, signingPassword)
        sign(publishing.publications)
    }
}
