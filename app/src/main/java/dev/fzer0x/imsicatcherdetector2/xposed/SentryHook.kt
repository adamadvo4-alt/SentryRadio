package dev.fzer0x.imsicatcherdetector2.xposed

import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Message
import android.os.Parcel
import android.os.UserHandle
import android.telephony.TelephonyManager
import android.telephony.SubscriptionManager
import android.telephony.CellInfo
import android.telephony.CellSignalStrength
import android.telephony.CellSignalStrengthLte
import android.telephony.CellSignalStrengthGsm
import android.telephony.CellIdentity
import android.telephony.CellIdentityLte
import android.telephony.CellIdentityGsm
import android.telephony.CellIdentityWcdma
import android.telephony.CellIdentityNr
import android.telephony.ServiceState
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.ConcurrentHashMap

class SentryHook : IXposedHookLoadPackage {

    private val ACTION_EVENT = "dev.fzer0x.imsicatcherdetector2.FORENSIC_EVENT"
    private val ACTION_REQUEST_UPDATE = "dev.fzer0x.imsicatcherdetector2.REQUEST_UPDATE"
    private val ACTION_SETTINGS_CHANGED = "dev.fzer0x.imsicatcherdetector2.SETTINGS_CHANGED"
    private val PREFS_NAME = "sentry_settings"
    private val KEY_BLOCK_GSM = "block_gsm"
    private val KEY_REJECT_A50 = "reject_a50"
    private val KEY_APP_ENABLED = "app_enabled"

    private val blockGsm = AtomicReference(false)
    private val rejectA50 = AtomicReference(false)
    private val appEnabled = AtomicReference(true)

    private var settingsContext: Context? = null
    
    // Performance optimization: Enhanced caching with LRU eviction
    private val hookCache = ConcurrentHashMap<String, CacheEntry>()
    private val CACHE_DURATION = 5000L // 5 seconds
    private val MAX_CACHE_SIZE = 500 // Increased from 100
    
    // Cache entry with access tracking
    private data class CacheEntry(
        val timestamp: Long,
        var accessCount: Long = 0,
        var lastAccess: Long = System.currentTimeMillis()
    )
    
    // Performance metrics
    private var cacheHits = 0L
    private var cacheMisses = 0L
    
    // Precompiled regex patterns for ciphering detection (Fallback)
    private val cipheringPatterns = listOf(
        "CIPHERING\\s*[:=]\\s*OFF".toRegex(),
        "CIPHERING\\s*[:=]\\s*0".toRegex(),
        "CIPHERING\\s*[:=]\\s*FALSE".toRegex(),
        "ENCRYPTION\\s*[:=]\\s*FALSE".toRegex(),
        "A5/0".toRegex(),
        "NO\\s*CIPHER".toRegex(),
        "CIPHER\\s*DISABLED".toRegex()
    )

    // RIL Unsolicited Response Constants
    private val RIL_UNSOL_RESPONSE_NEW_SMS = 1003
    private val RIL_UNSOL_ON_SS = 1015
    private val RIL_UNSOL_STK_CC_ALPHA_NOTIFY = 1044
    private val RIL_UNSOL_CIPHERING_INFO = 1042 // Qualcomm specific common ID

    override fun handleLoadPackage(lpparam: LoadPackageParam) {
        if (lpparam.packageName == "android") {
            hookTelephonyRegistry(lpparam)
        }
        if (lpparam.packageName == "com.android.phone") {
            hookServiceStateTracker(lpparam)
            hookInboundSmsHandler(lpparam)
            setupUpdateListener(lpparam)
            setupSettingsReceiver(lpparam)
            hookRilCiphering(lpparam)
            loadSettingsFromPreferences(lpparam)
        }
        if (lpparam.packageName == "dev.fzer0x.imsicatcherdetector2") {
            hookAppStartup(lpparam)
            hookXposedCheck(lpparam)
        }

        // Stealth: Hide Sentry Radio and Magisk from other apps
        if (lpparam.packageName != "dev.fzer0x.imsicatcherdetector2" &&
            lpparam.packageName != "android" &&
            lpparam.packageName != "com.android.phone" &&
            lpparam.packageName != "com.android.systemui") {
            hookPackageManager(lpparam)
        }
    }

    private fun hookPackageManager(lpparam: LoadPackageParam) {
        try {
            val pmClass = XposedHelpers.findClass("android.app.ApplicationPackageManager", lpparam.classLoader)
            val targetPackage = "dev.fzer0x.imsicatcherdetector2"
            val hideList = listOf(targetPackage, "com.topjohnwu.superuser")

            XposedBridge.hookAllMethods(pmClass, "getInstalledPackages", object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val packages = param.result as? MutableList<*> ?: return
                    val it = packages.iterator()
                    while (it.hasNext()) {
                        val info = it.next()
                        val pName = XposedHelpers.getObjectField(info, "packageName") as? String
                        if (hideList.contains(pName)) it.remove()
                    }
                }
            })

            XposedBridge.hookAllMethods(pmClass, "getInstalledApplications", object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val apps = param.result as? MutableList<*> ?: return
                    val it = apps.iterator()
                    while (it.hasNext()) {
                        val info = it.next()
                        val pName = XposedHelpers.getObjectField(info, "packageName") as? String
                        if (hideList.contains(pName)) it.remove()
                    }
                }
            })

            XposedBridge.hookAllMethods(pmClass, "getPackageInfo", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val pName = param.args[0] as? String
                    if (hideList.contains(pName)) {
                        param.throwable = PackageManager.NameNotFoundException(pName)
                    }
                }
            })

            XposedBridge.hookAllMethods(pmClass, "getApplicationInfo", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val pName = param.args[0] as? String
                    if (hideList.contains(pName)) {
                        param.throwable = PackageManager.NameNotFoundException(pName)
                    }
                }
            })

            XposedBridge.hookAllMethods(pmClass, "queryIntentActivities", object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val activities = param.result as? MutableList<*> ?: return
                    val it = activities.iterator()
                    while (it.hasNext()) {
                        val resolveInfo = it.next()
                        val activityInfo = XposedHelpers.getObjectField(resolveInfo, "activityInfo")
                        val pName = XposedHelpers.getObjectField(activityInfo, "packageName") as? String
                        if (hideList.contains(pName)) it.remove()
                    }
                }
            })
        } catch (e: Throwable) {}
    }

    private fun loadSettingsFromPreferences(lpparam: LoadPackageParam) {
        try {
            val phoneAppClass = XposedHelpers.findClass("com.android.internal.telephony.PhoneApp", lpparam.classLoader)
            XposedHelpers.findAndHookMethod(phoneAppClass, "onCreate", object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val context = param.thisObject as Context
                    settingsContext = context
                    try {
                        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                        blockGsm.set(prefs.getBoolean(KEY_BLOCK_GSM, false))
                        rejectA50.set(prefs.getBoolean(KEY_REJECT_A50, false))
                        appEnabled.set(prefs.getBoolean(KEY_APP_ENABLED, true))
                        XposedBridge.log("SentryHook: Settings loaded from SharedPreferences - BlockGSM: ${blockGsm.get()}, RejectA50: ${rejectA50.get()}, AppEnabled: ${appEnabled.get()}")
                    } catch (e: Exception) {
                        XposedBridge.log("SentryHook: Failed to load settings from SharedPreferences: ${e.message}")
                    }
                }
            })
        } catch (e: Throwable) {
            XposedBridge.log("SentryHook: Error hooking for preferences loading: ${e.message}")
        }
    }

    private fun setupSettingsReceiver(lpparam: LoadPackageParam) {
        try {
            val phoneAppClass = XposedHelpers.findClass("com.android.internal.telephony.PhoneApp", lpparam.classLoader)
            XposedHelpers.findAndHookMethod(phoneAppClass, "onCreate", object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val context = param.thisObject as Context
                    val filter = IntentFilter(ACTION_SETTINGS_CHANGED)
                    context.registerReceiver(object : BroadcastReceiver() {
                        override fun onReceive(ctx: Context, intent: Intent) {
                            blockGsm.set(intent.getBooleanExtra("blockGsm", false))
                            rejectA50.set(intent.getBooleanExtra("rejectA50", false))
                            appEnabled.set(intent.getBooleanExtra("appEnabled", true))
                            try {
                                val prefs = ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                                prefs.edit()
                                    .putBoolean(KEY_BLOCK_GSM, blockGsm.get())
                                    .putBoolean(KEY_REJECT_A50, rejectA50.get())
                                    .putBoolean(KEY_APP_ENABLED, appEnabled.get())
                                    .apply()
                            } catch (e: Exception) {}
                            XposedBridge.log("SentryHook: Settings updated & persisted - BlockGSM: ${blockGsm.get()}, RejectA50: ${rejectA50.get()}, AppEnabled: ${appEnabled.get()}")
                        }
                    }, filter, Context.RECEIVER_EXPORTED)
                }
            })
        } catch (e: Throwable) {
            XposedBridge.log("SentryHook: Failed to setup settings receiver: ${e.message}")
        }
    }

    private fun hookRilCiphering(lpparam: LoadPackageParam) {
        try {
            val rilClass = XposedHelpers.findClass("com.android.internal.telephony.RIL", lpparam.classLoader)
            XposedBridge.hookAllMethods(rilClass, "processUnsolicited", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    if (!appEnabled.get()) return 
                    
                    val responseArg = param.args[0] ?: return
                    
                    // Native Parcel Parsing (Manufacturer Consistent)
                    if (responseArg is Parcel) {
                        parseRilParcel(param.thisObject, responseArg)
                        // Note: We don't return here to allow the fallback string check to run 
                        // in case parcel parsing logic is incomplete for specific vendors.
                    }

                    val respStr = responseArg.toString().uppercase()
                    
                    // Performance optimization: Enhanced cache with precompiled patterns
                    val cacheKey = "cipher_${respStr.hashCode()}"
                    val now = System.currentTimeMillis()
                    
                    // Check cache with LRU tracking
                    val cachedEntry = hookCache[cacheKey]
                    if (cachedEntry != null) {
                        if (now - cachedEntry.timestamp < CACHE_DURATION) {
                            cachedEntry.accessCount++
                            cachedEntry.lastAccess = now
                            cacheHits++
                            return // Skip processing if recently checked
                        } else {
                            hookCache.remove(cacheKey)
                        }
                    }
                    
                    cacheMisses++
                    
                    // Cleanup cache if too large with intelligent eviction
                    if (hookCache.size > MAX_CACHE_SIZE) {
                        evictLeastUsefulHookEntries(now)
                    }
                    
                    // Add to cache
                    hookCache[cacheKey] = CacheEntry(now, 1L, now)

                    // Use precompiled patterns for better performance
                    val isCipheringOff = cipheringPatterns.any { pattern ->
                        pattern.containsMatchIn(respStr)
                    }

                    if (isCipheringOff) {
                        triggerCipheringAlert(param.thisObject, "Regex Detection: $respStr")
                    }
                }
            })
        } catch (e: Throwable) {
            XposedBridge.log("SentryHook: Error hooking RIL: ${e.message}")
        }
    }

    private fun parseRilParcel(rilObject: Any, p: Parcel) {
        val pos = p.dataPosition()
        try {
            val responseId = p.readInt()
            
            when (responseId) {
                RIL_UNSOL_CIPHERING_INFO -> {
                    // Qualcomm/Standard Ciphering Info structure
                    // Usually: [int status] where 0 = OFF, 1 = ON
                    val status = p.readInt()
                    if (status == 0) {
                        XposedBridge.log("SentryHook: NATIVE RIL PARCEL - Ciphering OFF detected (ID: $responseId)")
                        triggerCipheringAlert(rilObject, "Native RIL Parcel (ID: $responseId, Status: $status)")
                    }
                }
                RIL_UNSOL_ON_SS -> {
                    // Supplementary Service notification - can contain ciphering related status
                    // Parsing this requires deeper ASN.1/Vendor knowledge, 
                    // but we can look for specific indicators in the parcel data
                }
            }
        } catch (e: Exception) {
            // Silently fail parcel parsing to not crash RIL
        } finally {
            p.setDataPosition(pos)
        }
    }

    private fun triggerCipheringAlert(rilObject: Any, sourceInfo: String) {
        try {
            val context = XposedHelpers.getObjectField(rilObject, "mContext") as Context
            XposedBridge.log("SentryHook: CRITICAL - Unencrypted connection detected! Source: $sourceInfo")

            val intent = Intent().apply {
                putExtra("eventType", "CIPHERING_OFF")
                putExtra("description", "CRITICAL: Encryption disabled (A5/0) detected via Native RIL!")
                putExtra("severity", 10)
            }
            sendForensicBroadcast(context, intent)

            if (rejectA50.get()) {
                XposedBridge.log("SentryHook: SECURITY POLICY - Initiating controlled disconnect & reconnect.")
                
                val simSlot = try {
                    val phone = XposedHelpers.getObjectField(rilObject, "mPhone")
                    XposedHelpers.callMethod(phone, "getPhoneId") as Int
                } catch (e: Exception) { 0 }
                
                // Record A5/0 blocking event
                try {
                    val blockingIntent = Intent("dev.fzer0x.imsicatcherdetector2.RECORD_BLOCKING_EVENT")
                    blockingIntent.setPackage("dev.fzer0x.imsicatcherdetector2")
                    blockingIntent.putExtra("blockType", "A5/0_CIPHER_REJECTION")
                    blockingIntent.putExtra("description", "A5/0 unencrypted connection blocked on SIM $simSlot ($sourceInfo)")
                    blockingIntent.putExtra("severity", 10)
                    blockingIntent.putExtra("simSlot", simSlot)
                    context.sendBroadcast(blockingIntent)
                } catch (e: Exception) {}
                
                try {
                    val phone = XposedHelpers.getObjectField(rilObject, "mPhone")
                    val thread = Thread {
                        try {
                            XposedHelpers.callMethod(phone, "setRadioPower", false)
                            Thread.sleep(3000)
                            XposedHelpers.callMethod(phone, "setRadioPower", true)
                        } catch (e: Exception) {}
                    }
                    thread.isDaemon = true
                    thread.start()
                } catch (e: Exception) {}
            }
        } catch (e: Exception) {
            XposedBridge.log("SentryHook: Failed to trigger ciphering alert: ${e.message}")
        }
    }

    private fun hookServiceStateTracker(lpparam: LoadPackageParam) {
        try {
            val sstClass = XposedHelpers.findClass("com.android.internal.telephony.ServiceStateTracker", lpparam.classLoader)
            XposedHelpers.findAndHookMethod(sstClass, "handleMessage", Message::class.java, object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    if (!appEnabled.get()) return 
                    
                    val mSST = param.thisObject
                    val phone = XposedHelpers.getObjectField(mSST, "mPhone")
                    val context = XposedHelpers.getObjectField(phone, "mContext") as Context
                    val simSlot = XposedHelpers.callMethod(phone, "getPhoneId") as Int
                    val ss = XposedHelpers.getObjectField(mSST, "mSS") as ServiceState

                    val msg = param.args[0] as Message
                    if (msg.what == 1) { // EVENT_POLL_STATE_REGISTRATION
                        val ar = msg.obj
                        if (ar != null && ar.javaClass.name.contains("AsyncResult")) {
                            val exception = XposedHelpers.getObjectField(ar, "exception")
                            val result = XposedHelpers.getObjectField(ar, "result")
                            if (exception == null && result != null) {
                                val states = (result as? Array<String>) ?: emptyArray()
                                if (states != null && states.size > 13) {
                                    val rejectCause = states[13].toIntOrNull() ?: 0
                                    if (rejectCause != 0) {
                                        XposedBridge.log("SentryHook: Network Reject Cause detected: $rejectCause on SIM $simSlot")
                                        val intent = Intent().apply {
                                            putExtra("eventType", "IMSI_CATCHER_ALERT")
                                            putExtra("description", "Network Reject Cause #$rejectCause (IMSI Catcher Activity?) on SIM $simSlot")
                                            putExtra("severity", 9)
                                            putExtra("simSlot", simSlot)
                                        }
                                        sendForensicBroadcast(context, intent)
                                        
                                        // Record network reject as blocked event
                                        try {
                                            val blockingIntent = Intent("dev.fzer0x.imsicatcherdetector2.RECORD_BLOCKING_EVENT")
                                            blockingIntent.setPackage("dev.fzer0x.imsicatcherdetector2")
                                            blockingIntent.putExtra("blockType", "NETWORK_REJECT")
                                            blockingIntent.putExtra("description", "Network registration rejected with cause #$rejectCause on SIM $simSlot")
                                            blockingIntent.putExtra("severity", 9)
                                            blockingIntent.putExtra("simSlot", simSlot)
                                            context.sendBroadcast(blockingIntent)
                                        } catch (e: Exception) {}
                                    }
                                }
                            }
                        }
                    }

                    if (blockGsm.get() && isGsmRat(ss)) {
                        XposedBridge.log("SentryHook: GSM Detected - Blocking GSM connection on SIM $simSlot")

                        try { XposedHelpers.callMethod(ss, "setState", ServiceState.STATE_OUT_OF_SERVICE) } catch (e: Exception) {}
                        try {
                            val rilRef = XposedHelpers.getObjectField(phone, "mCi")
                            if (rilRef != null) { XposedHelpers.callMethod(rilRef, "setPreferredNetworkType", 11, null) }
                        } catch (e: Exception) {}

                        param.result = false

                        val intent = Intent().apply {
                            putExtra("eventType", "CELL_DOWNGRADE")
                            putExtra("description", "GSM Connection Blocked by Sentry Security on SIM $simSlot")
                            putExtra("severity", 9)
                            putExtra("simSlot", simSlot)
                        }
                        sendForensicBroadcast(context, intent)

                        try {
                            val blockingIntent = Intent("dev.fzer0x.imsicatcherdetector2.RECORD_BLOCKING_EVENT")
                            blockingIntent.setPackage("dev.fzer0x.imsicatcherdetector2")
                            blockingIntent.putExtra("blockType", "GSM_DOWNGRADE")
                            blockingIntent.putExtra("description", "GSM downgrade attempt blocked on SIM $simSlot")
                            blockingIntent.putExtra("severity", 9)
                            blockingIntent.putExtra("simSlot", simSlot)
                            context.sendBroadcast(blockingIntent)
                        } catch (e: Exception) {}
                    }

                    val lastCellInfo = (XposedHelpers.callMethod(mSST, "getAllCellInfo") as? List<CellInfo>) ?: emptyList()
                    if (!lastCellInfo.isNullOrEmpty() && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        processCellInfo(context, lastCellInfo, simSlot)
                    }
                }
            })
        } catch (e: Throwable) {
            XposedBridge.log("SentryHook: Error hooking SST: ${e.message}")
        }
    }

    private fun evictLeastUsefulHookEntries(now: Long) {
        val entriesToRemove = hookCache.entries
            .sortedWith(compareBy<Map.Entry<String, CacheEntry>> { now - it.value.timestamp }.thenBy { it.value.accessCount }.thenBy { now - it.value.lastAccess })
            .take(MAX_CACHE_SIZE / 10)
            .map { entry -> entry.key }
        entriesToRemove.forEach { key -> hookCache.remove(key) }
    }
    
    private fun isGsmRat(ss: ServiceState): Boolean {
        val voiceRat = XposedHelpers.callMethod(ss, "getVoiceNetworkType") as Int
        val dataRat = XposedHelpers.callMethod(ss, "getDataNetworkType") as Int
        val gsmTypes = listOf(TelephonyManager.NETWORK_TYPE_GSM, TelephonyManager.NETWORK_TYPE_GPRS, TelephonyManager.NETWORK_TYPE_EDGE)
        return gsmTypes.contains(voiceRat) || gsmTypes.contains(dataRat)
    }

    private fun hookTelephonyRegistry(lpparam: LoadPackageParam) {
        try {
            val registryClass = XposedHelpers.findClass("com.android.server.TelephonyRegistry", lpparam.classLoader)
            XposedBridge.hookAllMethods(registryClass, "notifyCellInfoForSubscriber", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return
                    val cellInfoList = (param.args.firstOrNull { it is List<*> } as? List<CellInfo>) ?: return
                    val context = XposedHelpers.getObjectField(param.thisObject, "mContext") as Context
                    val subId = param.args[0] as Int
                    val sm = context.getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE) as SubscriptionManager
                    val info = try { sm.getActiveSubscriptionInfo(subId) } catch (e: Exception) { null }
                    val simSlot = info?.simSlotIndex ?: 0
                    processCellInfo(context, cellInfoList, simSlot)
                }
            })
        } catch (e: Throwable) {}
    }

    private fun hookInboundSmsHandler(lpparam: LoadPackageParam) {
        try {
            XposedHelpers.findAndHookMethod(
                "com.android.internal.telephony.InboundSmsHandler",
                lpparam.classLoader, "dispatchSmsPdus",
                Array<ByteArray>::class.java, String::class.java, Int::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        if (!appEnabled.get()) return
                        
                        val context = XposedHelpers.getObjectField(param.thisObject, "mContext") as Context
                        val phone = XposedHelpers.getObjectField(param.thisObject, "mPhone")
                        val simSlot = XposedHelpers.callMethod(phone, "getPhoneId") as Int
                        val pdus = (param.args[0] as? Array<ByteArray>) ?: emptyArray()
                        val format = param.args[1] as String
                        val smsMessageClass = XposedHelpers.findClass("android.telephony.SmsMessage", lpparam.classLoader)
                        
                        for (pdu in pdus) {
                            val sms = XposedHelpers.callStaticMethod(smsMessageClass, "createFromPdu", pdu, format) ?: continue
                            val pid = XposedHelpers.callMethod(sms, "getProtocolIdentifier") as Int
                            
                            if (pid == 0x00 || pid == 0x40) {
                                XposedBridge.log("SentryHook: Silent SMS (PID $pid) BLOCKED on SIM $simSlot")
                                val intent = Intent().apply {
                                    putExtra("eventType", "SILENT_SMS")
                                    putExtra("description", "Silent SMS (Type-0) intercepted and blocked on SIM $simSlot")
                                    putExtra("severity", 9)
                                    putExtra("simSlot", simSlot)
                                }
                                sendForensicBroadcast(context, intent)

                                try {
                                    val blockingIntent = Intent("dev.fzer0x.imsicatcherdetector2.RECORD_BLOCKING_EVENT")
                                    blockingIntent.setPackage("dev.fzer0x.imsicatcherdetector2")
                                    blockingIntent.putExtra("blockType", "SILENT_SMS")
                                    blockingIntent.putExtra("description", "Type-0 Silent SMS blocked on SIM $simSlot")
                                    blockingIntent.putExtra("severity", 9)
                                    blockingIntent.putExtra("simSlot", simSlot)
                                    context.sendBroadcast(blockingIntent)
                                } catch (e: Exception) {}

                                param.result = null
                            }
                        }
                    }
                }
            )
        } catch (e: Throwable) {}
    }

    private fun hookXposedCheck(lpparam: LoadPackageParam) {
        try {
            XposedHelpers.findAndHookMethod(
                "dev.fzer0x.imsicatcherdetector2.ui.viewmodel.ForensicViewModel",
                lpparam.classLoader, "isXposedModuleActive",
                object : XC_MethodHook() { override fun beforeHookedMethod(param: MethodHookParam) { param.result = true } }
            )
        } catch (e: Throwable) {}
    }

    private fun sendForensicBroadcast(context: Context, intent: Intent) {
        intent.action = ACTION_EVENT
        intent.setPackage("dev.fzer0x.imsicatcherdetector2")
        intent.addFlags(Intent.FLAG_RECEIVER_FOREGROUND)
        try {
            val userAll = XposedHelpers.getStaticObjectField(UserHandle::class.java, "ALL") as UserHandle
            XposedHelpers.callMethod(context, "sendBroadcastAsUser", intent, userAll)
        } catch (e: Throwable) { context.sendBroadcast(intent) }
    }

    private fun setupUpdateListener(lpparam: LoadPackageParam) {
        try {
            val phoneAppClass = XposedHelpers.findClass("com.android.internal.telephony.PhoneApp", lpparam.classLoader)
            XposedHelpers.findAndHookMethod(phoneAppClass, "onCreate", object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val context = param.thisObject as Context
                    context.registerReceiver(object : BroadcastReceiver() {
                        override fun onReceive(ctx: Context, intent: Intent) { forceImmediateUpdate(ctx) }
                    }, IntentFilter(ACTION_REQUEST_UPDATE), Context.RECEIVER_EXPORTED)
                }
            })
        } catch (e: Throwable) {}
    }

    @SuppressLint("MissingPermission")
    private fun forceImmediateUpdate(context: Context) {
        try {
            val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val cellInfoList = tm.allCellInfo
                if (!cellInfoList.isNullOrEmpty()) processCellInfo(context, cellInfoList, -1)
            }
        } catch (e: Exception) {}
    }

    private fun hookAppStartup(lpparam: LoadPackageParam) {
        try {
            XposedHelpers.findAndHookMethod(
                "dev.fzer0x.imsicatcherdetector2.service.ForensicService",
                lpparam.classLoader, "onCreate", object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val context = param.thisObject as Context
                        val intent = Intent(ACTION_REQUEST_UPDATE).apply { setPackage(context.packageName) }
                        context.sendBroadcast(intent)
                    }
                }
            )
        } catch (e: Throwable) {}
    }

    @SuppressLint("NewApi")
    private fun processCellInfo(context: Context, cellInfoList: List<CellInfo>, simSlot: Int) {
        val activeCell = cellInfoList.firstOrNull { it.isRegistered } ?: cellInfoList.firstOrNull() ?: return
        val identity = activeCell.cellIdentity
        var dbm = -120
        var ta = -1
        try {
            val css = activeCell.cellSignalStrength
            dbm = when (css) {
                is CellSignalStrengthLte -> css.rsrp
                is CellSignalStrengthGsm -> css.dbm
                else -> -120
            }
            ta = when (css) {
                is CellSignalStrengthLte -> css.timingAdvance
                is CellSignalStrengthGsm -> css.bitErrorRate
                else -> -1
            }
            if (ta == Int.MAX_VALUE) ta = -1
        } catch (e: Exception) {}

        val intent = Intent().apply {
            putExtra("neighbors", cellInfoList.count { !it.isRegistered })
            putExtra("eventType", "RADIO_METRICS_UPDATE")
            if (dbm in -140..-30) putExtra("dbm", dbm)
            if (ta != -1) putExtra("ta", ta)
            putExtra("severity", 1)
            putExtra("simSlot", simSlot)
        }

        var foundIdentity = false
        when (identity) {
            is CellIdentityLte -> {
                if (identity.ci != Int.MAX_VALUE) {
                    intent.putExtra("cellId", identity.ci.toString())
                    intent.putExtra("pci", if (identity.pci != Int.MAX_VALUE) identity.pci else -1)
                    intent.putExtra("earfcn", if (identity.earfcn != Int.MAX_VALUE) identity.earfcn else -1)
                    intent.putExtra("tac", if (identity.tac != Int.MAX_VALUE) identity.tac else -1)
                    intent.putExtra("mcc", identity.mccString); intent.putExtra("mnc", identity.mncString)
                    intent.putExtra("networkType", "LTE"); foundIdentity = true
                }
            }
            is CellIdentityNr -> {
                if (identity.nci != Long.MAX_VALUE) {
                    intent.putExtra("cellId", identity.nci.toString())
                    intent.putExtra("pci", if (identity.pci != Int.MAX_VALUE) identity.pci else -1)
                    intent.putExtra("earfcn", if (identity.nrarfcn != Int.MAX_VALUE) identity.nrarfcn else -1)
                    intent.putExtra("tac", if (identity.tac != Int.MAX_VALUE) identity.tac else -1)
                    intent.putExtra("mcc", identity.mccString); intent.putExtra("mnc", identity.mncString)
                    
                    val networkType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        when {
                            identity.mncString == null || identity.mccString == null -> "5G NR (Unknown)"
                            is5gStandalone(identity) -> "5G SA (Standalone)"
                            is5gNonStandalone(identity) -> "5G NSA (EN-DC)"
                            else -> "5G NR"
                        }
                    } else { "5G NR" }
                    
                    intent.putExtra("networkType", networkType)
                    
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        intent.putExtra("nrArfcn", if (identity.nrarfcn != Int.MAX_VALUE) identity.nrarfcn else -1)
                        intent.putExtra("nrBand", extractNrBandFromArfcn(identity.nrarfcn))
                        intent.putExtra("nrState", extractNrState(identity))
                        intent.putExtra("nrDuplexMode", extractNrDuplexMode(identity))
                        intent.putExtra("nrMmWaveBand", isMmWaveBand(identity.nrarfcn))
                    }
                    
                    foundIdentity = true
                }
            }
            is CellIdentityGsm -> {
                if (identity.cid != Int.MAX_VALUE) {
                    intent.putExtra("cellId", identity.cid.toString())
                    intent.putExtra("lac", if (identity.lac != Int.MAX_VALUE) identity.lac else -1)
                    intent.putExtra("mcc", identity.mccString); intent.putExtra("mnc", identity.mncString)
                    intent.putExtra("networkType", "GSM"); foundIdentity = true
                }
            }
            is CellIdentityWcdma -> {
                if (identity.cid != Int.MAX_VALUE) {
                    intent.putExtra("cellId", identity.cid.toString())
                    intent.putExtra("lac", if (identity.lac != Int.MAX_VALUE) identity.lac else -1)
                    intent.putExtra("mcc", identity.mccString); intent.putExtra("mnc", identity.mncString)
                    intent.putExtra("networkType", "WCDMA"); foundIdentity = true
                }
            }
        }
        if (foundIdentity) sendForensicBroadcast(context, intent)
    }
    
    private fun is5gStandalone(identity: CellIdentityNr): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val endcSupport = XposedHelpers.callMethod(identity, "getEndcSupport") as? Boolean
                if (endcSupport == false) return true
                val nrStatus = XposedHelpers.callMethod(identity, "getNrStatus") as? Int
                if (nrStatus == 1) return true
                val lteBand = XposedHelpers.callMethod(identity, "getBandwidth") as? Int
                if (lteBand == null || lteBand == 0) return true
            }
            false
        } catch (e: Exception) { false }
    }
    
    private fun is5gNonStandalone(identity: CellIdentityNr): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val endcSupport = XposedHelpers.callMethod(identity, "getEndcSupport") as? Boolean
                if (endcSupport == true) return true
                val nrStatus = XposedHelpers.callMethod(identity, "getNrStatus") as? Int
                if (nrStatus == 2) return true
            }
            false
        } catch (e: Exception) { false }
    }
    
    private fun extractNrBandFromArfcn(nrarfcn: Int): String {
        if (nrarfcn == Int.MAX_VALUE) return "---"
        return when {
            nrarfcn in 422000..434000 -> "n1"
            nrarfcn in 386000..399000 -> "n3"
            nrarfcn in 1738000..1788000 -> "n257"
            nrarfcn in 2014667..2026667 -> "n258"
            nrarfcn in 2220000..2260000 -> "n260"
            nrarfcn in 2425000..2475000 -> "n261"
            nrarfcn in 460000..480000 -> "n5"
            nrarfcn in 514000..524000 -> "n7"
            nrarfcn in 869000..904000 -> "n8"
            nrarfcn in 371000..376000 -> "n20"
            nrarfcn in 620000..680000 -> "n28"
            nrarfcn in 1730000..1780000 -> "n66"
            nrarfcn in 422000..440000 -> "n71"
            nrarfcn in 3650000..3700000 -> "n77"
            nrarfcn in 4150000..4350000 -> "n78"
            else -> "n${nrarfcn / 10000}"
        }
    }
    
    private fun extractNrState(identity: CellIdentityNr): String {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val nrStatus = XposedHelpers.callMethod(identity, "getNrStatus") as? Int
                when (nrStatus) {
                    0 -> "IDLE"; 1 -> "CONNECTED_SA"; 2 -> "CONNECTED_NSA"; 3 -> "CONNECTED"; else -> "UNKNOWN"
                }
            } else { "UNKNOWN" }
        } catch (e: Exception) { "UNKNOWN" }
    }
    
    private fun extractNrDuplexMode(identity: CellIdentityNr): String {
        val band = extractNrBandFromArfcn(if (identity.nrarfcn != Int.MAX_VALUE) identity.nrarfcn else 0)
        return when {
            band.startsWith("n7") || band.startsWith("n38") || band.startsWith("n40") || band.startsWith("n41") || band.startsWith("n77") || band.startsWith("n78") || band.startsWith("n79") -> "TDD"
            band.startsWith("n1") || band.startsWith("n3") || band.startsWith("n5") || band.startsWith("n8") || band.startsWith("n20") || band.startsWith("n28") -> "FDD"
            else -> "UNKNOWN"
        }
    }
    
    private fun isMmWaveBand(nrarfcn: Int): Boolean {
        if (nrarfcn == Int.MAX_VALUE) return false
        val band = extractNrBandFromArfcn(nrarfcn)
        return band in listOf("n257", "n258", "n260", "n261", "n262", "n263")
    }
}
