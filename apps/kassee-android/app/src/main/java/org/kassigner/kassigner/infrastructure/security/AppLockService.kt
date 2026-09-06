package org.kassigner.kassigner.infrastructure.security

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import kotlin.coroutines.resume
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.suspendCancellableCoroutine

enum class LockDelay(val milliseconds: Long) { IMMEDIATELY(0), ONE_MINUTE(60_000), FIVE_MINUTES(300_000) }

data class AppLockState(
    val enabled: Boolean = false,
    val locked: Boolean = false,
    val delay: LockDelay = LockDelay.IMMEDIATELY,
    val hideSwitcherPreview: Boolean = true,
    val authenticating: Boolean = false,
    val privacyCoverSuspendedForSession: Boolean = false,
    val error: String? = null,
)

internal enum class AppAuthenticationStatus { SUCCEEDED, FAILED }

internal data class AppAuthenticationResult(
    val status: AppAuthenticationStatus,
    val error: String? = null,
)

internal fun interface AppAuthenticator {
    suspend fun authenticate(activity: FragmentActivity, title: String): AppAuthenticationResult
}

internal class AndroidAppAuthenticator(context: Context) : AppAuthenticator {
    private val applicationContext = context.applicationContext

    override suspend fun authenticate(activity: FragmentActivity, title: String): AppAuthenticationResult {
        val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        return when (BiometricManager.from(applicationContext).canAuthenticate(authenticators)) {
            BiometricManager.BIOMETRIC_SUCCESS -> prompt(activity, title, authenticators)
            else -> AppAuthenticationResult(
                AppAuthenticationStatus.FAILED,
                "Biometrics or a device credential are unavailable.",
            )
        }
    }

    private suspend fun prompt(
        activity: FragmentActivity,
        title: String,
        authenticators: Int,
    ): AppAuthenticationResult = suspendCancellableCoroutine { continuation ->
        fun finish(result: AppAuthenticationResult) {
            if (continuation.isActive) continuation.resume(result)
        }

        val prompt = BiometricPrompt(activity, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) =
                finish(AppAuthenticationResult(AppAuthenticationStatus.SUCCEEDED))

            override fun onAuthenticationError(code: Int, message: CharSequence) {
                val visible = when (code) {
                    BiometricPrompt.ERROR_USER_CANCELED, BiometricPrompt.ERROR_CANCELED -> null
                    else -> message.toString()
                }
                finish(AppAuthenticationResult(AppAuthenticationStatus.FAILED, visible))
            }
        })
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setAllowedAuthenticators(authenticators)
            .build()
        prompt.authenticate(info)
        continuation.invokeOnCancellation { prompt.cancelAuthentication() }
    }
}

class AppLockService internal constructor(
    context: Context,
    private val authenticator: AppAuthenticator,
    private val nowMillis: () -> Long,
) {
    constructor(context: Context) : this(
        context = context,
        authenticator = AndroidAppAuthenticator(context.applicationContext),
        nowMillis = System::currentTimeMillis,
    )

    private val applicationContext = context.applicationContext
    private val store = applicationContext.getSharedPreferences("kassigner.security.v1", Context.MODE_PRIVATE)
    private val mutableState = MutableStateFlow(load())
    val state: StateFlow<AppLockState> = mutableState.asStateFlow()
    private var backgroundedAt: Long? = null

    suspend fun enable(activity: FragmentActivity): Boolean = authenticate(activity, "Enable App Lock").also { success ->
        if (success) update(mutableState.value.copy(enabled = true, locked = false))
    }

    suspend fun disable(activity: FragmentActivity): Boolean = authenticate(activity, "Disable App Lock").also { success ->
        if (success) update(mutableState.value.copy(enabled = false, locked = false, privacyCoverSuspendedForSession = false))
    }

    suspend fun unlock(activity: FragmentActivity): Boolean {
        val current = mutableState.value
        if (!current.enabled || !current.locked) return true
        return authenticate(activity, "Unlock KasSigner").also { success ->
            if (success) update(mutableState.value.copy(locked = false))
        }
    }

    suspend fun unlockFromPrivacyCover(activity: FragmentActivity): Boolean {
        val current = mutableState.value
        if (!current.enabled) return false
        val success = if (current.locked) authenticate(activity, "Open protected content") else true
        if (success) update(mutableState.value.copy(locked = false, privacyCoverSuspendedForSession = true))
        return success
    }

    suspend fun authorizePrivacyCoverChange(activity: FragmentActivity): Boolean =
        authenticate(activity, "Change Privacy Cover settings")

    fun suspendPrivacyCoverForCurrentSession() =
        update(mutableState.value.copy(privacyCoverSuspendedForSession = true))

    fun clearError() = update(mutableState.value.copy(error = null))
    fun setDelay(delay: LockDelay) = update(mutableState.value.copy(delay = delay))
    fun setHideSwitcherPreview(enabled: Boolean) = update(mutableState.value.copy(hideSwitcherPreview = enabled))

    fun onBackground() {
        backgroundedAt = nowMillis()
        val current = mutableState.value
        val locked = current.enabled && current.delay == LockDelay.IMMEDIATELY
        update(current.copy(locked = current.locked || locked, privacyCoverSuspendedForSession = false))
    }

    fun onForeground() {
        val since = backgroundedAt ?: return
        backgroundedAt = null
        val current = mutableState.value
        if (current.enabled && nowMillis() - since >= current.delay.milliseconds) {
            update(current.copy(locked = true))
        }
    }

    private suspend fun authenticate(activity: FragmentActivity, title: String): Boolean {
        if (mutableState.value.authenticating) return false
        update(mutableState.value.copy(authenticating = true, error = null))
        return try {
            val result = authenticator.authenticate(activity, title)
            val success = result.status == AppAuthenticationStatus.SUCCEEDED
            update(mutableState.value.copy(authenticating = false, error = result.error))
            success
        } catch (cancellation: CancellationException) {
            update(mutableState.value.copy(authenticating = false))
            throw cancellation
        }
    }

    private fun load(): AppLockState {
        val enabled = store.getBoolean("enabled", false)
        val delay = runCatching { LockDelay.valueOf(store.getString("delay", "IMMEDIATELY")!!) }.getOrDefault(LockDelay.IMMEDIATELY)
        return AppLockState(
            enabled = enabled,
            locked = enabled,
            delay = delay,
            hideSwitcherPreview = store.getBoolean("hide_switcher", true),
        )
    }

    private fun update(value: AppLockState) {
        mutableState.value = value
        store.edit()
            .putBoolean("enabled", value.enabled)
            .putString("delay", value.delay.name)
            .putBoolean("hide_switcher", value.hideSwitcherPreview)
            .apply()
    }
}
