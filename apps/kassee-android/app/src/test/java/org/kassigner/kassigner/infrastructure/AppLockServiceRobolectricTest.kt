package org.kassigner.kassigner.infrastructure

import androidx.fragment.app.FragmentActivity
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kassigner.kassigner.infrastructure.security.AppAuthenticationResult
import org.kassigner.kassigner.infrastructure.security.AppAuthenticationStatus
import org.kassigner.kassigner.infrastructure.security.AppAuthenticator
import org.kassigner.kassigner.infrastructure.security.AppLockService
import org.kassigner.kassigner.infrastructure.security.AppLockState
import org.kassigner.kassigner.infrastructure.security.LockDelay
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class AppLockServiceRobolectricTest {
    private val context get() = ApplicationProvider.getApplicationContext<android.content.Context>()

    @Before
    fun clear() {
        context.getSharedPreferences("kassigner.security.v1", 0).edit().clear().commit()
    }

    @After
    fun cleanup() = clear()

    @Test
    fun defaultsAndPersistedSecuritySettingsAreFailClosed() {
        val defaults = AppLockState()
        assertFalse(defaults.enabled)
        assertFalse(defaults.locked)
        assertTrue(defaults.hideSwitcherPreview)
        assertFalse(defaults.authenticating)
        assertFalse(defaults.privacyCoverSuspendedForSession)

        val service = appLock(FakeAuthenticator.success())
        assertFalse(service.state.value.enabled)
        assertFalse(service.state.value.locked)
        assertTrue(service.state.value.hideSwitcherPreview)

        service.setDelay(LockDelay.FIVE_MINUTES)
        service.setHideSwitcherPreview(false)
        val restored = appLock(FakeAuthenticator.success())
        assertEquals(LockDelay.FIVE_MINUTES, restored.state.value.delay)
        assertFalse(restored.state.value.hideSwitcherPreview)
    }

    @Test
    fun enableDisableAndUnlockTransitionsRequireAuthentication() = runBlocking {
        val activity = activity()
        val authenticator = FakeAuthenticator.success()
        val service = appLock(authenticator)

        assertTrue(service.enable(activity))
        assertTrue(service.state.value.enabled)
        assertFalse(service.state.value.locked)
        assertFalse(service.state.value.authenticating)
        assertEquals(listOf("Enable App Lock"), authenticator.titles)

        authenticator.result = authFailed("denied")
        val callsBeforeUnlockedUnlock = authenticator.calls
        assertTrue(service.unlock(activity))
        assertEquals(callsBeforeUnlockedUnlock, authenticator.calls)

        authenticator.result = authSucceeded()
        service.suspendPrivacyCoverForCurrentSession()
        assertTrue(service.disable(activity))
        assertFalse(service.state.value.enabled)
        assertFalse(service.state.value.locked)
        assertFalse(service.state.value.privacyCoverSuspendedForSession)

        val failedEnable = appLock(FakeAuthenticator.failed("nope"))
        assertFalse(failedEnable.enable(activity))
        assertFalse(failedEnable.state.value.enabled)
        assertEquals("nope", failedEnable.state.value.error)
        failedEnable.clearError()
        assertNull(failedEnable.state.value.error)
    }

    @Test
    fun unlocksPersistedLockedStateOnlyAfterSuccess() = runBlocking {
        context.getSharedPreferences("kassigner.security.v1", 0)
            .edit().putBoolean("enabled", true).commit()
        val activity = activity()
        val authenticator = FakeAuthenticator.failed("denied")
        val service = appLock(authenticator)
        assertTrue(service.state.value.locked)

        assertFalse(service.unlock(activity))
        assertTrue(service.state.value.locked)

        authenticator.result = authSucceeded()
        assertTrue(service.unlock(activity))
        assertFalse(service.state.value.locked)
    }

    @Test
    fun privacyCoverUnlockHonorsEnabledLockedAndSessionState() = runBlocking {
        val activity = activity()
        val disabledAuthenticator = FakeAuthenticator.success()
        val disabled = appLock(disabledAuthenticator)
        assertFalse(disabled.unlockFromPrivacyCover(activity))
        assertEquals(0, disabledAuthenticator.calls)

        val unlockedAuthenticator = FakeAuthenticator.success()
        val unlocked = appLock(unlockedAuthenticator)
        assertTrue(unlocked.enable(activity))
        val callsBeforeCover = unlockedAuthenticator.calls
        assertTrue(unlocked.unlockFromPrivacyCover(activity))
        assertEquals(callsBeforeCover, unlockedAuthenticator.calls)
        assertFalse(unlocked.state.value.locked)
        assertTrue(unlocked.state.value.privacyCoverSuspendedForSession)

        context.getSharedPreferences("kassigner.security.v1", 0)
            .edit().clear().putBoolean("enabled", true).commit()
        val lockedAuthenticator = FakeAuthenticator.success()
        val locked = appLock(lockedAuthenticator)
        assertTrue(locked.unlockFromPrivacyCover(activity))
        assertEquals(listOf("Open protected content"), lockedAuthenticator.titles)
        assertFalse(locked.state.value.locked)
        assertTrue(locked.state.value.privacyCoverSuspendedForSession)

        val direct = appLock(FakeAuthenticator.success())
        direct.suspendPrivacyCoverForCurrentSession()
        assertTrue(direct.state.value.privacyCoverSuspendedForSession)
    }

    @Test
    fun backgroundPolicyPreservesLockAndClearsSessionCoverOverride() = runBlocking {
        val activity = activity()
        val clock = TestClock(1_000)
        val immediate = appLock(FakeAuthenticator.success(), clock)
        assertTrue(immediate.enable(activity))
        immediate.suspendPrivacyCoverForCurrentSession()
        immediate.onBackground()
        assertTrue(immediate.state.value.locked)
        assertFalse(immediate.state.value.privacyCoverSuspendedForSession)

        context.getSharedPreferences("kassigner.security.v1", 0).edit().clear().commit()
        val disabled = appLock(FakeAuthenticator.success(), TestClock(1_000))
        disabled.onBackground()
        assertFalse(disabled.state.value.locked)

        val delayedAuthenticator = FakeAuthenticator.success()
        context.getSharedPreferences("kassigner.security.v1", 0)
            .edit().clear().putBoolean("enabled", true).commit()
        val delayed = appLock(delayedAuthenticator, TestClock(1_000))
        assertTrue(delayed.unlock(activity))
        delayed.setDelay(LockDelay.ONE_MINUTE)
        delayed.onBackground()
        assertFalse(delayed.state.value.locked)
    }

    @Test
    fun foregroundUsesExactConfiguredDelayBoundary() = runBlocking {
        val activity = activity()
        val clock = TestClock(1_000)
        val authenticator = FakeAuthenticator.success()
        val service = appLock(authenticator, clock)
        assertTrue(service.enable(activity))
        service.setDelay(LockDelay.ONE_MINUTE)
        service.onBackground()
        assertFalse(service.state.value.locked)
        clock.now = 61_000
        service.onForeground()
        assertTrue(service.state.value.locked)

        context.getSharedPreferences("kassigner.security.v1", 0).edit().clear().commit()
        val disabledClock = TestClock(1_000)
        val disabled = appLock(FakeAuthenticator.success(), disabledClock)
        disabled.setDelay(LockDelay.ONE_MINUTE)
        disabled.onBackground()
        disabledClock.now = 1_000_000
        disabled.onForeground()
        assertFalse(disabled.state.value.locked)
    }

    @Test
    fun rejectsConcurrentAuthenticationAndClearsBusyState() = runBlocking {
        val activity = activity()
        val authenticator = BlockingAuthenticator()
        val service = appLock(authenticator)
        val first = async(start = CoroutineStart.UNDISPATCHED) { service.authorizePrivacyCoverChange(activity) }
        assertFalse("first authentication must suspend until the authenticator completes", first.isCompleted)
        assertEquals(1, authenticator.calls)
        assertTrue(service.state.value.authenticating)

        assertFalse(service.authorizePrivacyCoverChange(activity))
        assertEquals(1, authenticator.calls)

        authenticator.release.complete(authSucceeded())
        assertTrue(first.await())
        assertFalse(service.state.value.authenticating)
    }

    @Test
    fun cancellationClearsAuthenticationBusyState() = runBlocking {
        val activity = activity()
        val authenticator = CancelingAuthenticator()
        val service = appLock(authenticator)
        val job = async(start = CoroutineStart.UNDISPATCHED) { service.authorizePrivacyCoverChange(activity) }
        assertFalse("authentication must remain in-flight until cancellation", job.isCompleted)
        assertEquals(1, authenticator.calls)
        assertTrue(service.state.value.authenticating)
        job.cancelAndJoin()
        assertFalse(service.state.value.authenticating)
    }

    private fun appLock(
        authenticator: AppAuthenticator,
        clock: TestClock = TestClock(1_000),
    ) = AppLockService(context, authenticator) { clock.now }

    private fun activity(): FragmentActivity =
        Robolectric.buildActivity(FragmentActivity::class.java).setup().get()

    private class TestClock(var now: Long)

    private class FakeAuthenticator private constructor(
        var result: AppAuthenticationResult,
    ) : AppAuthenticator {
        var calls: Int = 0
        val titles = mutableListOf<String>()

        override suspend fun authenticate(activity: FragmentActivity, title: String): AppAuthenticationResult {
            calls += 1
            titles += title
            return result
        }

        companion object {
            fun success() = FakeAuthenticator(authSucceeded())
            fun failed(message: String) = FakeAuthenticator(AppLockServiceRobolectricTest.authFailed(message))
        }
    }

    private class BlockingAuthenticator : AppAuthenticator {
        val release = CompletableDeferred<AppAuthenticationResult>()
        var calls: Int = 0

        override suspend fun authenticate(activity: FragmentActivity, title: String): AppAuthenticationResult {
            calls += 1
            if (calls == 1) return release.await()
            return authFailed("unexpected concurrent authentication")
        }
    }

    private class CancelingAuthenticator : AppAuthenticator {
        var calls: Int = 0

        override suspend fun authenticate(activity: FragmentActivity, title: String): AppAuthenticationResult {
            calls += 1
            awaitCancellation()
        }
    }

    companion object {
        private fun authSucceeded() = AppAuthenticationResult(AppAuthenticationStatus.SUCCEEDED)
        private fun authFailed(message: String) = AppAuthenticationResult(AppAuthenticationStatus.FAILED, message)
    }
}
