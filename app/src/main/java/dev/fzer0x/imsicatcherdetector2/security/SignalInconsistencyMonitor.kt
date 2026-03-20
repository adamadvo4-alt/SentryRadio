package dev.fzer0x.imsicatcherdetector2.security

import android.util.Log

/**
 * B2: Signal Inconsistency Monitoring (SNR/SINR Analysis)
 * Detects IMSI Catchers by identifying suspicious signal-to-noise ratios.
 * IMSI catchers often have very high power (RSRP) but may have unusual SNR/SINR 
 * characteristics compared to legitimate base stations.
 */
class SignalInconsistencyMonitor {
    private val TAG = "SignalInconsistencyMonitor"
    
    // Thresholds for suspicious activity
    private val EXTREME_POWER_THRESHOLD = -50 // dBm (Higher than this is very close/strong)
    private val LOW_SNR_HIGH_POWER_THRESHOLD = 5 // dB (High power but poor quality could indicate interference/fake cell)
    private val UNUSUAL_POWER_JUMP_THRESHOLD = 20 // dB jump between readings
    
    private val lastSignalStrength = mutableMapOf<Int, Int>() // Slot to last DBM
    
    /**
     * Analyzes signal metrics for inconsistencies.
     * @return true if the signal characteristics are suspicious.
     */
    fun analyze(slot: Int, dbm: Int, snr: Int?): Boolean {
        // 1. Extreme Power Check
        if (dbm > EXTREME_POWER_THRESHOLD && dbm != 0) {
            Log.w(TAG, "ALERT: Extremely high signal power detected: ${dbm}dBm on SIM $slot")
            return true
        }
        
        // 2. High Power / Low Quality Check (C/I Ratio)
        if (snr != null && dbm > -70 && snr < LOW_SNR_HIGH_POWER_THRESHOLD) {
            Log.w(TAG, "ALERT: High power (${dbm}dBm) but low SNR (${snr}dB) detected on SIM $slot")
            return true
        }
        
        // 3. Unusual Power Jump Check
        val lastDbm = lastSignalStrength[slot]
        if (lastDbm != null) {
            val jump = Math.abs(dbm - lastDbm)
            if (jump > UNUSUAL_POWER_JUMP_THRESHOLD && dbm != -120 && lastDbm != -120) {
                Log.w(TAG, "ALERT: Unusual signal power jump detected: ${jump}dB on SIM $slot")
                // A massive jump without moving much is highly suspicious
                lastSignalStrength[slot] = dbm
                return true
            }
        }
        
        lastSignalStrength[slot] = dbm
        return false
    }
}
