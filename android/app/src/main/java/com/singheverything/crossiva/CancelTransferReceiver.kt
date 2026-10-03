package com.singheverything.crossiva

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

class CancelTransferReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action
        
        when (action) {
            ACTION_CANCEL_RECEIVE -> {
                AndroidTcpReceiver.cancel()
            }
            ACTION_CANCEL_SEND -> {
                LocalSyncManager.cancelTransfer()
            }
        }
    }

    companion object {
        const val ACTION_CANCEL_RECEIVE = "com.singheverything.crossiva.ACTION_CANCEL_RECEIVE"
        const val ACTION_CANCEL_SEND = "com.singheverything.crossiva.ACTION_CANCEL_SEND"
    }
}
