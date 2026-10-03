package com.bunty.clipsync

import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.content.Context
import android.os.Build
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * MacPushReceiver — Android-side subscriber for the Mac→Android BLE Notify path.
 *
 * Flow:
 *   1. [start] is called after pairing/BLE connection.
 *   2. Connects to the Mac's GATT server, discovers services.
 *   3. Subscribes to SEND_REQUEST_CHAR (C11C5AC3) by writing CCCD descriptor.
 *   4. [onCharacteristicChanged] fires whenever Mac calls updateValue(). Every value must be an
 *      authenticated BLE v2 envelope (see [BleControlProtocol]); anything else is ignored:
 *      - text          → decrypt → write to clipboard
 *      - file_incoming → spin up AndroidTcpReceiver → send tcp_ready ACK via WAKEUP_CHAR
 *   5. On disconnect, retries up to 3 times with 2-second backoff.
 */
object MacPushReceiver {

    private const val TAG = "MacPushReceiver"
    private const val MAX_RETRIES = 3
    private const val RETRY_DELAY_MS = 2000L

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var gatt: BluetoothGatt? = null
    private var retryCount = 0
    private var isSubscribed = false
    private var isConnecting = false
    private var retryJob: Job? = null

    /** Start listening. Call this after pairing is confirmed and BLE address is known. */
    @Synchronized
    fun start(context: Context) {
        if (isSubscribed || isConnecting) {
            return
        }
        val macAddress = DeviceManager.getMacBleAddress(context)
        if (macAddress.isNullOrEmpty()) {
            Log.w(TAG, "No Mac BLE address — cannot start MacPushReceiver")
            return
        }
        retryCount = 0
        try {
            connect(context, macAddress)
        } catch (e: SecurityException) {
            Log.e(TAG, "SecurityException: Missing BLUETOOTH_CONNECT permission", e)
        }
    }

    @Synchronized
    fun stop() {
        retryJob?.cancel()
        retryJob = null
        gatt?.disconnect()
        gatt?.close()
        gatt = null
        isSubscribed = false
        isConnecting = false
        retryCount = 0
    }

    // ── Private helpers ─────────────────────────────────────────────────────

    private fun connect(context: Context, address: String) {
        val btManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        val adapter = btManager?.adapter ?: return
        if (!adapter.isEnabled) {
            Log.w(TAG, "Bluetooth disabled — cannot connect")
            return
        }
        val device = try {
            adapter.getRemoteDevice(address)
        } catch (e: Exception) {
            Log.e(TAG, "Invalid address: $address", e)
            return
        }

        isConnecting = true

        val callback = object : BluetoothGattCallback() {

            override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
                when (newState) {
                    BluetoothProfile.STATE_CONNECTED -> {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                            g.requestMtu(512)
                        } else {
                            g.discoverServices()
                        }
                    }
                    BluetoothProfile.STATE_DISCONNECTED -> {
                        Log.w(TAG, "GATT disconnected (status=$status); isSubscribed=$isSubscribed")
                        isSubscribed = false
                        isConnecting = false
                        g.close()
                        if (gatt == g) gatt = null
                        if (retryCount < MAX_RETRIES) {
                            retryCount++
                            retryJob = scope.launch {
                                delay(RETRY_DELAY_MS)
                                connect(context, address)
                            }
                        } else {
                            Log.w(TAG, "Max retries reached — MacPushReceiver idle")
                        }
                    }
                }
            }

            override fun onMtuChanged(g: BluetoothGatt, mtu: Int, status: Int) {
                g.discoverServices()
            }

            override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    Log.w(TAG, "Service discovery failed ($status)")
                    g.disconnect()
                    return
                }
                val service = g.getService(BLEScanner.SERVICE_UUID)
                if (service == null) {
                    Log.w(TAG, "ClipSync service not found on Mac")
                    g.disconnect()
                    return
                }
                val sendRequestChar = service.getCharacteristic(WakeupPingSender.SEND_REQUEST_CHAR_UUID)
                if (sendRequestChar == null) {
                    Log.w(TAG, "SendRequest char not found — Mac may be running older firmware")
                    g.disconnect()
                    return
                }

                // Enable notifications locally
                g.setCharacteristicNotification(sendRequestChar, true)

                // Write to CCCD descriptor to enable server-side notifications
                val cccd = sendRequestChar.getDescriptor(WakeupPingSender.CCCD_UUID)
                if (cccd == null) {
                    Log.w(TAG, "CCCD descriptor not found on SendRequest char")
                    g.disconnect()
                    return
                }

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    g.writeDescriptor(cccd, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
                } else {
                    @Suppress("DEPRECATION")
                    cccd.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                    @Suppress("DEPRECATION")
                    g.writeDescriptor(cccd)
                }
            }

            override fun onDescriptorWrite(
                g: BluetoothGatt,
                descriptor: BluetoothGattDescriptor,
                status: Int
            ) {
                if (descriptor.uuid == WakeupPingSender.CCCD_UUID && status == BluetoothGatt.GATT_SUCCESS) {
                    isSubscribed = true
                    isConnecting = false
                    retryCount = 0  // reset retry count on successful subscription
                } else {
                    isConnecting = false
                    Log.w(TAG, "CCCD write failed (status=$status) — retrying connection")
                    g.disconnect()
                }
            }

            // API < 33
            @Deprecated("Deprecated in Java")
            override fun onCharacteristicChanged(
                g: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic
            ) {
                if (characteristic.uuid == WakeupPingSender.SEND_REQUEST_CHAR_UUID) {
                    @Suppress("DEPRECATION")
                    handlePush(context, g, characteristic.value ?: return)
                }
            }

            // API 33+
            override fun onCharacteristicChanged(
                g: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                value: ByteArray
            ) {
                if (characteristic.uuid == WakeupPingSender.SEND_REQUEST_CHAR_UUID) {
                    handlePush(context, g, value)
                }
            }
        }

        gatt = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            device.connectGatt(context, false, callback, android.bluetooth.BluetoothDevice.TRANSPORT_LE)
        } else {
            @Suppress("DEPRECATION")
            device.connectGatt(context, false, callback)
        }
    }

    // ── Push handler ─────────────────────────────────────────────────────────

    private fun handlePush(context: Context, gatt: BluetoothGatt, value: ByteArray) {
        // Authenticate first: nothing below runs for a forged, replayed or malformed message.
        val result = AndroidBle.inbound.process(
            value, AndroidBle.rootKey(context), System.currentTimeMillis(), AndroidBleInbound.NOTIFICATION_TYPES)
        val msg = when (result) {
            is AndroidBleInbound.Result.Rejected -> {
                Log.w(TAG, "Rejected BLE push: ${result.reason}")
                AndroidBle.noteIfLegacyPeer(context, value)
                return
            }
            is AndroidBleInbound.Result.Accepted -> result.message
        }

        when (msg.type) {
            BleControlProtocol.Type.DIAGNOSTIC_ACK -> {
                context.sendBroadcast(
                    android.content.Intent("com.bunty.clipsync.DIAGNOSTIC_ACK").setPackage(context.packageName))
            }
            BleControlProtocol.Type.PUSH_TEXT -> {
                val decrypted = decryptBase64(context, msg.string(BleControlProtocol.Field.CONTENT)!!) ?: run {
                    Log.e(TAG, "Failed to decrypt text push from Mac")
                    return
                }
                val text = decrypted.toString(Charsets.UTF_8)

                // Handle text/image payload and write to clipboard safely
                ClipboardGhostActivity.copyToClipboard(context, text)
            }
            BleControlProtocol.Type.FILE_INCOMING -> {
                val size = msg.uint(BleControlProtocol.Field.SIZE)!!
                val filename = msg.string(BleControlProtocol.Field.FILE_NAME)!!
                val port = msg.uint(BleControlProtocol.Field.PORT)!!.toInt()
                if (port < 1024) { Log.w(TAG, "Rejected BLE push: privileged port"); return }

                scope.launch {
                    // Spin up the TCP server and wait for it to be ready
                    val ready = AndroidTcpReceiver.start(context, port, size, filename)
                    if (ready) {
                        // Send tcp_ready ACK back to Mac via the WAKEUP_CHAR (Android→Mac write)
                        sendTcpReadyAck(context, port, replyTo = msg.messageId)
                    } else {
                        Log.e(TAG, "AndroidTcpReceiver failed to start")
                    }
                }
            }
            BleControlProtocol.Type.TEXT_INCOMING -> {
                // Large clipboard text that didn't fit in a BLE notify; received over TCP and
                // pushed to the system clipboard instead of saved to Downloads.
                val size = msg.uint(BleControlProtocol.Field.SIZE)!!
                val port = msg.uint(BleControlProtocol.Field.PORT)!!.toInt()
                if (port < 1024) { Log.w(TAG, "Rejected BLE push: privileged port"); return }

                scope.launch {
                    val ready = AndroidTcpReceiver.startForText(context, port, size) { text ->

                        // Add to history and set clipboard (ClipboardGhostActivity handles both text and images safely)
                        ClipboardGhostActivity.copyToClipboard(context, text)
                    }

                    if (ready) {
                        sendTcpReadyAck(context, port, replyTo = msg.messageId)
                    } else {
                        Log.e(TAG, "AndroidTcpReceiver.startForText failed to start")
                    }
                }
            }
            BleControlProtocol.Type.SETTING -> {
                // Schema allows exactly one field, ultra_fast, with value 0 or 1.
                DeviceManager.setUltraFastModeEnabled(context, msg.uint(BleControlProtocol.Field.ULTRA_FAST) == 1L)
            }
            BleControlProtocol.Type.PING -> {
                // Mac is pre-pinging to get a fresh Android IP before starting a transfer.
                // The ping_ack echoes this ping's messageId so the Mac accepts it only once.
                scope.launch { sendPingAck(context, replyTo = msg.messageId) }
            }
            else -> Log.w(TAG, "Rejected BLE push: unexpected type")
        }
    }

    private fun sendPingAck(context: Context, replyTo: ByteArray) {
        val androidIp = getLocalIp() ?: return
        val battery = try {
            val bm = context.getSystemService(Context.BATTERY_SERVICE) as android.os.BatteryManager
            bm.getIntProperty(android.os.BatteryManager.BATTERY_PROPERTY_CAPACITY)
        } catch (_: Exception) { -1 }

        val ping = WakeupPing(
            localIp = androidIp,
            tcpPort = 8766,
            payloadSize = 0,
            payloadType = "ping_ack",
            battery = if (battery >= 0) battery else null,
            replyTo = replyTo
        )

        WakeupPingSender.send(
            context = context,
            ping = ping,
            onSent = { _, _ -> },
            onFailed = { reason -> Log.w(TAG, "ping_ack failed: $reason") }
        )
    }

    private fun sendTcpReadyAck(context: Context, port: Int, replyTo: ByteArray) {
        val androidIp = getLocalIp() ?: return
        val battery = try {
            val bm = context.getSystemService(Context.BATTERY_SERVICE) as android.os.BatteryManager
            bm.getIntProperty(android.os.BatteryManager.BATTERY_PROPERTY_CAPACITY)
        } catch (_: Exception) { -1 }

        val ping = WakeupPing(
            localIp = androidIp,
            tcpPort = port,
            payloadSize = 0,
            payloadType = "tcp_ready",
            battery = if (battery >= 0) battery else null,
            replyTo = replyTo
        )

        WakeupPingSender.send(
            context = context,
            ping = ping,
            onSent = { _, _ -> },
            onFailed = { reason -> Log.w(TAG, "tcp_ready ACK failed: $reason") }
        )
    }

    // ── Network helper ────────────────────────────────────────────────────────

    private fun getLocalIp(): String? {
        try {
            val ifaces = java.net.NetworkInterface.getNetworkInterfaces() ?: return null
            for (iface in ifaces.asSequence()) {
                if (!iface.isUp || iface.isLoopback) continue
                for (addr in iface.inetAddresses.asSequence()) {
                    if (!addr.isLoopbackAddress && addr is java.net.Inet4Address) {
                        return addr.hostAddress
                    }
                }
            }
        } catch (_: Exception) {}
        return null
    }

    // ── Decryption (AES-256-GCM, matches Mac's encryption) ───────────────────

    private fun decryptBase64(context: Context, base64: String): ByteArray? {
        return try {
            val hexKey = DeviceManager.getEncryptionKey(context) ?: return null
            val keyBytes = hexKey.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            val combined = android.util.Base64.decode(base64, android.util.Base64.DEFAULT)
            // combined = nonce(12) + ciphertext + GCM tag(16)
            if (combined.size <= 12) return null
            val nonce = combined.copyOfRange(0, 12)
            val ciphertext = combined.copyOfRange(12, combined.size)
            val key = SecretKeySpec(keyBytes, "AES")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, nonce))
            cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            Log.e(TAG, "Decryption error", e)
            null
        }
    }
}
