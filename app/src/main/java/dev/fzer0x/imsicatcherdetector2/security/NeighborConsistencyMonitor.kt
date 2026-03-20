package dev.fzer0x.imsicatcherdetector2.security

import android.util.Log

/**
 * B3: Neighbor Cell Inconsistency Monitoring
 * Detects IMSI Catchers by identifying suspicious neighbor cell configurations.
 * Fake cells often have no neighbors or inconsistent neighbor lists to prevent 
 * the phone from handing over to a legitimate cell.
 */
class NeighborConsistencyMonitor {
    private val TAG = "NeighborConsistencyMonitor"
    
    private val lastNeighborCount = mutableMapOf<Int, Int>() // Slot to count
    
    /**
     * Analyzes neighbor cell data.
     * @return true if the configuration is suspicious.
     */
    fun analyze(slot: Int, neighborCount: Int, servingSignalDbm: Int): Boolean {
        // 1. "Isolated Cell" Check
        // If we have a very strong signal but ZERO neighbors, it's highly suspicious.
        // Legitimate towers in urban/suburban areas almost always have neighbors.
        if (neighborCount == 0 && servingSignalDbm > -80) {
            Log.w(TAG, "ALERT: Serving cell has ZERO neighbors despite strong signal (${servingSignalDbm}dBm) on SIM $slot")
            return true
        }
        
        // 2. Sudden Neighbor Loss
        val lastCount = lastNeighborCount[slot]
        if (lastCount != null && lastCount >= 3 && neighborCount == 0) {
            Log.w(TAG, "ALERT: Sudden loss of all neighbor cells on SIM $slot")
            return true
        }
        
        lastNeighborCount[slot] = neighborCount
        return false
    }
}
