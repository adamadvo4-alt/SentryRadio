package dev.fzer0x.imsicatcherdetector2.security

import android.location.Location
import android.util.Log
import java.util.concurrent.ConcurrentHashMap

/**
 * B1: Stationary Cell Monitoring (Lock-in Mode)
 * Detects IMSI Catcher activity by monitoring cell changes while the device is stationary.
 */
class StationaryCellMonitor {
    private val TAG = "StationaryCellMonitor"
    
    // Thresholds
    private val STATIONARY_DISTANCE_THRESHOLD = 50.0 // meters
    private val LOCK_IN_DURATION_MS = 10 * 60 * 1000 // 10 minutes to "lock in" a location
    
    private data class LocationLock(
        val baseLocation: Location,
        val firstSeenTimestamp: Long,
        val lockedCellIds: MutableSet<String> = mutableSetOf()
    )
    
    private var currentLock: LocationLock? = null
    
    /**
     * Updates the monitor with current location and cell data.
     * @return true if a suspicious cell change was detected at a stationary location.
     */
    fun update(location: Location, cellId: String, networkType: String): Boolean {
        val now = System.currentTimeMillis()
        
        val lock = currentLock
        if (lock == null) {
            currentLock = LocationLock(location, now).apply { lockedCellIds.add(cellId) }
            return false
        }
        
        val distance = location.distanceTo(lock.baseLocation)
        
        if (distance > STATIONARY_DISTANCE_THRESHOLD) {
            // Device is moving, reset lock
            Log.d(TAG, "Device moving (dist: ${distance}m), resetting stationary lock")
            currentLock = LocationLock(location, now).apply { lockedCellIds.add(cellId) }
            return false
        }
        
        // Device is stationary
        val durationAtLocation = now - lock.firstSeenTimestamp
        
        if (durationAtLocation > LOCK_IN_DURATION_MS) {
            // We are "Locked In"
            if (!lock.lockedCellIds.contains(cellId)) {
                // Suspicious: Cell changed while we are stationary at a known location
                Log.w(TAG, "ALERT: Cell changed from ${lock.lockedCellIds} to $cellId while stationary!")
                
                // If it's a completely new cell ID at this stationary spot, it's suspicious
                // (Note: In some cases, carriers have multiple cells covering one spot, 
                // but a sudden change to a single new cell can be an IMSI catcher)
                return true
            }
        } else {
            // Still in "Learning" phase for this location
            lock.lockedCellIds.add(cellId)
        }
        
        return false
    }
}
