package androidx.biometric.integration.testapp

import android.annotation.SuppressLint
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricPrompt
import java.security.KeyStore
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** A message payload to be encrypted by the application. */
internal const val PAYLOAD = "hello"

/** A name used to refer to an app-specified secret key. */
private const val KEY_NAME = "mySecretKey"

/** The name of the Android keystore provider instance. */
private const val KEYSTORE_INSTANCE = "AndroidKeyStore"

/**
 * Returns a [BiometricPrompt.CryptoObject] for crypto-based authentication,
 * which can be configured to [allowBiometricAuth] and/or [allowDeviceCredentialAuth].
 */
@Suppress("DEPRECATION")
@SuppressLint("TrulyRandom")
@RequiresApi(Build.VERSION_CODES.M)
internal fun createCryptoObject(
    allowBiometricAuth: Boolean,
    allowDeviceCredentialAuth: Boolean
): BiometricPrompt.CryptoObject {
    val keyPurpose = KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT

    val keySpec =
        Api23Impl.createKeyGenParameterSpecBuilder(KEY_NAME, keyPurpose).run {
            Api23Impl.setBlockModeGCM(this)
            Api23Impl.setEncryptionPaddingNone(this)
            Api23Impl.setUserAuthenticationRequired(this, true)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                Api30Impl.setUserAuthenticationParameters(
                    this,
                    timeout = 0,
                    allowBiometricAuth,
                    allowDeviceCredentialAuth
                )
            } else {
                Api23Impl.setUserAuthenticationValidityDurationSeconds(this, -1)
            }

            Api23Impl.buildKeyGenParameterSpec(this)
        }

    // Generate and store the key in the Android keystore.
    KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_INSTANCE).run {
        init(keySpec as AlgorithmParameterSpec)
        generateKey()
    }

    // Initialize cipher with GCMParameterSpec (IV)
    val cipher = getCipher().apply {
        val iv = ByteArray(12) // Recommended IV length for GCM
        SecureRandom().nextBytes(iv)
        val spec = GCMParameterSpec(128, iv) // 128-bit authentication tag
        init(Cipher.ENCRYPT_MODE, getSecretKey(), spec)
    }

    return BiometricPrompt.CryptoObject(cipher)
}

/** Returns the cipher that will be used for encryption. */
@RequiresApi(Build.VERSION_CODES.M)
private fun getCipher(): Cipher {
    return Cipher.getInstance(
        "${KeyProperties.KEY_ALGORITHM_AES}/" +
        "${KeyProperties.BLOCK_MODE_GCM}/" +
        "${KeyProperties.ENCRYPTION_PADDING_NONE}"
    )
}

/** Returns the previously generated secret key from keystore. */
private fun getSecretKey(): SecretKey {
    val keyStore = KeyStore.getInstance(KEYSTORE_INSTANCE).apply { load(null) }
    return keyStore.getKey(KEY_NAME, null) as SecretKey
}

@RequiresApi(Build.VERSION_CODES.R)
private object Api30Impl {
    fun setUserAuthenticationParameters(
        builder: KeyGenParameterSpec.Builder,
        timeout: Int,
        allowBiometricAuth: Boolean,
        allowDeviceCredentialAuth: Boolean
    ) {
        var keyType = 0
        if (allowBiometricAuth) {
            keyType = keyType or KeyProperties.AUTH_BIOMETRIC_STRONG
        }
        if (allowDeviceCredentialAuth) {
            keyType = keyType or KeyProperties.AUTH_DEVICE_CREDENTIAL
        }
        builder.setUserAuthenticationParameters(timeout, keyType)
    }
}

@RequiresApi(Build.VERSION_CODES.M)
private object Api23Impl {
    fun createKeyGenParameterSpecBuilder(
        keyName: String,
        keyPurpose: Int
    ): KeyGenParameterSpec.Builder = KeyGenParameterSpec.Builder(keyName, keyPurpose)

    fun setBlockModeGCM(builder: KeyGenParameterSpec.Builder) {
        builder.setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    }

    fun setEncryptionPaddingNone(builder: KeyGenParameterSpec.Builder) {
        builder.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    }

    fun setUserAuthenticationRequired(
        builder: KeyGenParameterSpec.Builder,
        userAuthenticationRequired: Boolean
    ) {
        builder.setUserAuthenticationRequired(userAuthenticationRequired)
    }

    @Suppress("DEPRECATION")
    fun setUserAuthenticationValidityDurationSeconds(
        builder: KeyGenParameterSpec.Builder,
        userAuthenticationValidityDurationSeconds: Int
    ) {
        builder.setUserAuthenticationValidityDurationSeconds(
            userAuthenticationValidityDurationSeconds
        )
    }

    fun buildKeyGenParameterSpec(builder: KeyGenParameterSpec.Builder): KeyGenParameterSpec {
        return builder.build()
    }
}
