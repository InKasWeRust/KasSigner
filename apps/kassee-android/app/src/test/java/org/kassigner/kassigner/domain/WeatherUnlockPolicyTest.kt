package org.kassigner.kassigner.domain

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kassigner.kassigner.domain.weather.WeatherUnlockPolicy
import org.kassigner.kassigner.domain.weather.WeatherUnlockTarget

class WeatherUnlockPolicyTest {
    @Test fun unlockRequiresConfiguredTargetAndExactNormalizedTapCount() {
        assertTrue(WeatherUnlockPolicy.shouldUnlock(WeatherUnlockTarget.TEMPERATURE, WeatherUnlockTarget.TEMPERATURE, 3, 3))
        assertFalse(WeatherUnlockPolicy.shouldUnlock(WeatherUnlockTarget.TEMPERATURE, WeatherUnlockTarget.LOCATION, 3, 3))
        assertFalse(WeatherUnlockPolicy.shouldUnlock(WeatherUnlockTarget.TEMPERATURE, WeatherUnlockTarget.TEMPERATURE, 2, 3))
        assertTrue(WeatherUnlockPolicy.shouldUnlock(WeatherUnlockTarget.LOCATION, WeatherUnlockTarget.LOCATION, 2, 0))
        assertTrue(WeatherUnlockPolicy.shouldUnlock(WeatherUnlockTarget.LOCATION, WeatherUnlockTarget.LOCATION, 7, 99))
    }
}
