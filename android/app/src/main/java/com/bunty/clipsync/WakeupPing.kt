package com.bunty.clipsync

import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.content.Context
import android.os.Build
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.UUID

/**
 * 30-byte BLE wakeup ping sent from Android to Mac before each TCP transfer.
 *
 * The ping tells the Mac:
 *  - Where Android's TCP server is listening (ip + port)
 *  - How large the incoming payload is (so Mac can show progress)
 *  - What type of content is coming ("text" | "image" | "file")
 *
 * Serialised as compact JSON to stay under the BLE MTU (≤ 512 bytes).
 * Typical payload: {"ip":"192.168.1.15","p":8765,"s":2048,"t":"text"} — 54 bytes.
 */
data class WakeupPing(
    val localIp:     String,
    val tcpPort:     Int    = LocalSyncManager.TCP_PORT,
    val payloadSize: Long,
    val payloadType: String,  // "text" | "image" | "file"
    val directPayload: String? = null,
    val battery: Int? = null,
    val network: String? = null,
    val deviceName: String? = null,
    val isDiagnostic: Boolean = false,
    /** messageId of the Mac request this answers (required for ping_ack / tcp_ready). */
    val replyTo: ByteArray? = null
) {
    /** The authenticated BLE message type for [payloadType] (or diagnostic). */
    fun messageType(): BleControlProtocol.Type? =
        if (isDiagnostic) BleControlProtocol.Type.DIAGNOSTIC
        else BleControlProtocol.Type.forAndroidPayloadType(payloadType)

    /** TLV fields for the BLE v2 envelope. Free text is cleaned and length-limited. */
    fun toFields(): Map<BleControlProtocol.Field, ByteArray> {
        val f = LinkedHashMap<BleControlProtocol.Field, ByteArray>()
        if (directPayload != null) {
            f[BleControlProtocol.Field.DIRECT_PAYLOAD] = BleControlProtocol.utf8(directPayload)
        } else {
            if (localIp.isNotEmpty() && BleControlProtocol.isValidIpv4OrEmpty(localIp)) {
                f[BleControlProtocol.Field.IP] = BleControlProtocol.utf8(localIp)
            }
            if (tcpPort in 1..65535) f[BleControlProtocol.Field.PORT] = BleControlProtocol.u16(tcpPort)
        }
        f[BleControlProtocol.Field.SIZE] = BleControlProtocol.i64(payloadSize.coerceAtLeast(0))
        if (battery != null && battery in 0..100) f[BleControlProtocol.Field.BATTERY] = BleControlProtocol.u8(battery)
        network?.let { cleanText(it, 128) }?.let { f[BleControlProtocol.Field.NETWORK] = it }
        deviceName?.let { cleanText(it, 128) }?.let { f[BleControlProtocol.Field.DEVICE_NAME] = it }
        replyTo?.let { f[BleControlProtocol.Field.REPLY_TO] = it }
        return f
    }

    private fun cleanText(s: String, maxBytes: Int): ByteArray? {
        val out = StringBuilder()
        var bytes = 0
        for (ch in s.filterNot { Character.getType(it) == Character.CONTROL.toInt() }) {
            val n = ch.toString().toByteArray(Charsets.UTF_8).size
            if (bytes + n > maxBytes) break
            out.append(ch)
            bytes += n
        }
        return if (out.isEmpty()) null else out.toString().toByteArray(Charsets.UTF_8)
    }
}

/**
 * Android's BLE security state: the shared inbound gate (one bounded replay cache for all
 * Mac → Android messages) and the pairing key lookup.
 */
object AndroidBle {
    val inbound = AndroidBleInbound()

    fun rootKey(context: Context): ByteArray? =
        DeviceManager.getEncryptionKey(context)?.let {
            try { TcpFrameProtocol.rootKey(it) } catch (e: TcpFrameProtocol.FrameException) { null }
        }

    /** Authenticated envelope for [ping], or null if not paired / the type is unknown. */
    fun envelopeFor(context: Context, ping: WakeupPing): ByteArray? {
        val rootKey = rootKey(context) ?: return null
        val type = ping.messageType() ?: return null
        return BleControlProtocol.encode(
            type, ping.toFields(), BleControlProtocol.newMessageId(), System.currentTimeMillis(),
            BleControlProtocol.authKey(rootKey))
    }

    @Volatile private var legacyPeerNoticeShown = false

    /**
     * An old (pre-v2) Mac sends plain JSON instead of an authenticated envelope. It is never
     * trusted or answered in the old format; the user is told once to update the Mac.
     */
    fun noteIfLegacyPeer(context: Context, value: ByteArray) {
        if (legacyPeerNoticeShown || value.isEmpty() || value[0] != '{'.code.toByte()) return
        legacyPeerNoticeShown = true
        DeviceManager.notifySecurityError(context, "Update ClipSync on your Mac — this version can't sync with it securely.")
    }

    /** The Mac's LAN endpoint from a device-info read, only if the envelope verifies. */
    fun verifiedMacEndpoint(context: Context, value: ByteArray): Pair<String, Int>? {
        noteIfLegacyPeer(context, value)
        val result = inbound.process(value, rootKey(context), System.currentTimeMillis(), AndroidBleInbound.DEVICE_INFO_TYPES)
        val msg = (result as? AndroidBleInbound.Result.Accepted)?.message ?: return null
        val ip = msg.string(BleControlProtocol.Field.IP) ?: return null
        val port = msg.uint(BleControlProtocol.Field.PORT)?.toInt() ?: return null
        return ip to port
    }
}

// ── BLE Wakeup Sender ─────────────────────────────────────────────────────────

/**
 * Connects to the Mac's BLE GATT server, performs a single GATT session that:
 *   1. Reads the DeviceName characteristic → parses {"name":..., "ip":...} to get the Mac's live IP.
 *   2. Writes the WakeupPing to the Wakeup characteristic.
 *   3. Disconnects.
 *
 * This completely replaces mDNS/Bonjour for MAC IP discovery. No hardcoded IPs.
 * The resolved Mac IP is returned via [onReady] so LocalSyncManager can use it for TCP.
 */
object WakeupPingSender {

    private const val TAG = "WakeupPing"

    /** Must match the characteristic UUID registered in WakeupReceiver.swift on Mac. */
    val WAKEUP_CHAR_UUID: UUID = UUID.fromString("C11C5AC2-0001-1000-8000-00805F9B34FB")

    /** Mac→Android push characteristic: Mac calls updateValue() to notify Android of incoming content. */
    val SEND_REQUEST_CHAR_UUID: UUID = UUID.fromString("C11C5AC3-0001-1000-8000-00805F9B34FB")

    /** Standard GATT CCCD descriptor UUID — must be written to enable notifications. */
    val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

    /** DeviceName char UUID — Mac serves {"name":..., "ip":...} JSON from this. */
    private val DEVICE_NAME_CHAR_UUID: UUID = UUID.fromString("C11C5AC1-0001-1000-8000-00805F9B34FB")

    /** ClipSync service UUID — same as BLEScanner. */
    private val SERVICE_UUID: UUID = UUID.fromString("C11C5AC0-0001-1000-8000-00805F9B34FB")

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /**
     * Sends [ping] to the Mac via BLE in a single GATT session:
     * read DeviceName char (to get Mac's live IP) → write wakeup ping → disconnect.
     *
     * @param context   Application context for Bluetooth access.
     * @param ping      The wakeup payload (localIp = Android's IP, filled by caller).
     * @param onSent    Called with the Mac's resolved IP and Port when the write succeeds.
     * @param onFailed  Called with a reason string if anything fails.
     */
    fun send(
        context:  Context,
        ping:     WakeupPing,
        onSent:   (macIp: String, macPort: Int) -> Unit,
        onFailed: (String) -> Unit
    ) {
        val macAddress = DeviceManager.getMacBleAddress(context)
        if (macAddress.isNullOrEmpty()) {
            onFailed("No Mac BLE address stored — pair first")
            return
        }

        // Every control write is an authenticated v2 envelope; no key → nothing is sent.
        val pingBytes = try {
            AndroidBle.envelopeFor(context, ping)
        } catch (e: BleControlProtocol.BleException) {
            null
        } ?: run {
            onFailed("Not paired or unsupported message — BLE control message not sent")
            return
        }

        scope.launch {
            connectReadThenWrite(context, macAddress, pingBytes, ping, onSent, onFailed)
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private fun connectReadThenWrite(
        context:    Context,
        address:    String,
        pingData:   ByteArray,
        ping:       WakeupPing,
        onSent:     (macIp: String, macPort: Int) -> Unit,
        onFailed:   (String) -> Unit
    ) {
        val btManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        val adapter   = btManager?.adapter ?: run {
            onFailed("Bluetooth not available")
            return
        }

        if (!adapter.isEnabled) {
            onFailed("Bluetooth is disabled")
            return
        }

        val device = try {
            adapter.getRemoteDevice(address)
        } catch (e: IllegalArgumentException) {
            onFailed("Invalid BLE address: $address")
            return
        }


        val callback = object : BluetoothGattCallback() {
            private var ipReadDone = false
            private var writeAttempted = false
            private var resolvedMacIp: String = ""
            private var resolvedMacPort: Int = LocalSyncManager.TCP_PORT

            override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                        gatt.requestMtu(512)
                    } else {
                        gatt.discoverServices()
                    }
                } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                    if (!writeAttempted) {
                        Log.w(TAG, "BLE disconnected before write; resolvedIp=$resolvedMacIp, port=$resolvedMacPort")
                        // Even if write wasn't confirmed, if we got the IP, partial success
                        if (resolvedMacIp.isNotEmpty()) {
                            onSent(resolvedMacIp, resolvedMacPort)
                        } else {
                            onFailed("BLE disconnected before wakeup write")
                        }
                    }
                    gatt.close()
                }
            }

            override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
                gatt.discoverServices()
            }

            override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    onFailed("BLE service discovery failed ($status)")
                    gatt.close()
                    return
                }

                val service = gatt.getService(SERVICE_UUID)
                if (service == null) {
                    onFailed("ClipSync BLE service not found on Mac")
                    gatt.close()
                    return
                }

                // Step 1: Read the DeviceName characteristic to get Mac's live IP
                val nameChar = service.getCharacteristic(DEVICE_NAME_CHAR_UUID)
                if (nameChar != null && !ipReadDone) {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        gatt.readCharacteristic(nameChar)
                    } else {
                        @Suppress("DEPRECATION")
                        gatt.readCharacteristic(nameChar)
                    }
                } else {
                    // Fallback: skip read, write directly (will use cached IP)
                    Log.w(TAG, "DeviceName char not found; skipping IP read, going directly to write")
                    writeWakeupPing(gatt, service, pingData, resolvedMacIp, ::onFailed)
                }
            }

            @Suppress("DEPRECATION")
            override fun onCharacteristicRead(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                status: Int
            ) {
                if (characteristic.uuid == DEVICE_NAME_CHAR_UUID) {
                    if (status == BluetoothGatt.GATT_SUCCESS) {
                        // Only an authenticated device-info envelope may change the saved endpoint.
                        val endpoint = AndroidBle.verifiedMacEndpoint(context, characteristic.value ?: ByteArray(0))
                        if (endpoint != null) {
                            resolvedMacIp = endpoint.first
                            resolvedMacPort = endpoint.second
                            DeviceManager.saveMacLocalEndpoint(context, resolvedMacIp, resolvedMacPort)
                        } else {
                            Log.w(TAG, "Device info not authenticated; using cached IP")
                            resolvedMacIp = DeviceManager.getMacLocalIp(context) ?: ""
                            resolvedMacPort = DeviceManager.getMacLocalPort(context)
                        }
                    } else {
                        Log.w(TAG, "DeviceName read failed (status=$status); will use cached IP")
                        resolvedMacIp = DeviceManager.getMacLocalIp(context) ?: ""
                        resolvedMacPort = DeviceManager.getMacLocalPort(context)
                    }
                    ipReadDone = true

                    // Step 2: Now write the wakeup ping in the same connection
                    val service = gatt.getService(SERVICE_UUID)
                    if (service != null) {
                        writeWakeupPing(gatt, service, pingData, resolvedMacIp, ::onFailed)
                    } else {
                        onFailed("Service disappeared after IP read")
                        gatt.disconnect()
                    }
                }
            }

            // API 33+ version
            override fun onCharacteristicRead(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                value: ByteArray,
                status: Int
            ) {
                if (characteristic.uuid == DEVICE_NAME_CHAR_UUID) {
                    if (status == BluetoothGatt.GATT_SUCCESS) {
                        // Only an authenticated device-info envelope may change the saved endpoint.
                        val endpoint = AndroidBle.verifiedMacEndpoint(context, value)
                        if (endpoint != null) {
                            resolvedMacIp = endpoint.first
                            resolvedMacPort = endpoint.second
                            DeviceManager.saveMacLocalEndpoint(context, resolvedMacIp, resolvedMacPort)
                        } else {
                            Log.w(TAG, "Device info not authenticated; using cached IP")
                            resolvedMacIp = DeviceManager.getMacLocalIp(context) ?: ""
                            resolvedMacPort = DeviceManager.getMacLocalPort(context)
                        }
                    } else {
                        Log.w(TAG, "DeviceName read failed API33 (status=$status); using cached IP")
                        resolvedMacIp = DeviceManager.getMacLocalIp(context) ?: ""
                        resolvedMacPort = DeviceManager.getMacLocalPort(context)
                    }
                    ipReadDone = true

                    val service = gatt.getService(SERVICE_UUID)
                    if (service != null) {
                        writeWakeupPing(gatt, service, pingData, resolvedMacIp, ::onFailed)
                    } else {
                        onFailed("Service disappeared after IP read")
                        gatt.disconnect()
                    }
                }
            }

            override fun onCharacteristicWrite(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                status: Int
            ) {
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    writeAttempted = true
                    onSent(resolvedMacIp, resolvedMacPort)
                } else {
                    onFailed("BLE write failed (status $status)")
                }
                gatt.disconnect()
                gatt.close()
            }

            // Helper to keep both code paths DRY
            private fun onSent(ip: String, port: Int) = onSent.invoke(ip, port)
            private fun onFailed(msg: String) = onFailed.invoke(msg)
        }

        val gatt = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            device.connectGatt(context, false, callback, android.bluetooth.BluetoothDevice.TRANSPORT_LE)
        } else {
            @Suppress("DEPRECATION")
            device.connectGatt(context, false, callback)
        }

        // Safety: close the GATT after 10 seconds if nothing happened
        scope.launch {
            delay(10_000)
            try { gatt.close() } catch (_: Exception) {}
        }
    }

    private fun writeWakeupPing(
        gatt:       BluetoothGatt,
        service:    android.bluetooth.BluetoothGattService,
        data:       ByteArray,
        macIp:      String,
        onFailed:   (String) -> Unit
    ) {
        val wakeupChar = service.getCharacteristic(WAKEUP_CHAR_UUID)
        if (wakeupChar == null) {
            onFailed("Wakeup characteristic not found on Mac")
            gatt.close()
            return
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            gatt.writeCharacteristic(wakeupChar, data, BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT)
        } else {
            @Suppress("DEPRECATION")
            wakeupChar.value = data
            @Suppress("DEPRECATION")
            gatt.writeCharacteristic(wakeupChar)
        }
    }
}
