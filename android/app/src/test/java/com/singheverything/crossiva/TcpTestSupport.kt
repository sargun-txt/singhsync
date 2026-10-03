package com.singheverything.crossiva

import com.singheverything.crossiva.TcpFrameProtocol.FrameException
import com.singheverything.crossiva.TcpFrameProtocol.Header
import com.singheverything.crossiva.TcpFrameProtocol.Reason
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Shared helpers for protocol tests. */
object TcpTestSupport {

    fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    fun hexOf(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    /** protocol/tcp-v2-test-vectors.properties, shared with the Swift tests and the Python reference. */
    val vectors: Map<String, String> by lazy { loadVectors("tcp-v2-test-vectors.properties") }

    /** Loads a shared fixture file from the repository's protocol/ directory. */
    fun loadVectors(name: String): Map<String, String> {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null && !File(dir, "protocol/$name").exists()) dir = dir.parentFile
        val file = File(requireNotNull(dir) { "protocol/$name not found" }, "protocol/$name")
        return file.readLines(Charsets.UTF_8)
            .filter { it.isNotBlank() && !it.startsWith("#") && it.contains("=") }
            .associate { it.substringBefore("=").trim() to it.substringAfter("=").trim() }
    }

    sealed class Outcome {
        data class Success(val type: Byte, val name: String, val payload: List<Byte>) : Outcome()
        data class Rejected(val reason: Reason) : Outcome()
    }

    /** Mirrors AndroidTcpReceiver / ClipSyncServer: verified header, then chunks. */
    fun receive(wire: ByteArray, rootKey: ByteArray, direction: Byte, nowMs: Long,
                cache: TcpReplayCache? = null): Outcome = try {
        val inp = ByteArrayInputStream(wire)
        val h = TcpFrameProtocol.readVerifiedHeader(inp, rootKey, direction, nowMs, cache)
        val out = ByteArrayOutputStream()
        TcpFrameProtocol.readChunks(inp, h, rootKey) { out.write(it) }
        Outcome.Success(h.type, h.fileName.toString(Charsets.UTF_8), out.toByteArray().toList())
    } catch (e: FrameException) {
        Outcome.Rejected(e.reason)
    }

    fun success(type: Byte, name: String, payload: ByteArray) = Outcome.Success(type, name, payload.toList())

    fun header(type: Byte, direction: Byte, total: Long, chunk: Int, ts: Long, name: String = "",
               session: ByteArray = TcpFrameProtocol.newSessionId()) =
        Header(type, direction, total, chunk, ts, session, name.toByteArray(Charsets.UTF_8))

    /** Header + chunks via the real writer. Returns the wire and the individual chunk frames. */
    fun send(payload: ByteArray, h: Header, rootKey: ByteArray): Pair<ByteArray, List<ByteArray>> {
        val out = ByteArrayOutputStream()
        TcpFrameProtocol.writeTransfer(out, rootKey, h, ByteArrayInputStream(payload))
        val wire = out.toByteArray()
        return wire to splitChunks(wire, h)
    }

    fun headerLength(h: Header) = TcpFrameProtocol.FIXED_PREFIX_LENGTH + h.fileName.size + TcpFrameProtocol.MAC_LENGTH

    fun splitChunks(wire: ByteArray, h: Header): List<ByteArray> {
        val chunks = mutableListOf<ByteArray>()
        var pos = headerLength(h)
        while (pos < wire.size) {
            val len = ByteBuffer.wrap(wire, pos, 4).int
            chunks += wire.copyOfRange(pos, pos + 4 + len)
            pos += 4 + len
        }
        return chunks
    }

    /** Seals without the sender's length checks, for building deliberately wrong streams. */
    fun rawSeal(plain: ByteArray, rootKey: ByteArray, h: Header, index: Long): ByteArray {
        val iv = TcpFrameProtocol.newSessionId().copyOf(12)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(rootKey, "AES"), GCMParameterSpec(128, iv))
        cipher.updateAAD(TcpFrameProtocol.aad(h, index))
        val ct = cipher.doFinal(plain)
        return ByteBuffer.allocate(4 + 12 + ct.size).putInt(12 + ct.size).put(iv).put(ct).array()
    }

    /** Header for [declared] bytes followed by [payload] chunked at [h].chunkSize. */
    fun mismatchedStream(payload: ByteArray, h: Header, rootKey: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(TcpFrameProtocol.encodeHeader(h, TcpFrameProtocol.authKey(rootKey)))
        var off = 0
        var index = 0L
        while (off < payload.size) {
            val end = minOf(off + h.chunkSize, payload.size)
            out.write(rawSeal(payload.copyOfRange(off, end), rootKey, h, index))
            off = end
            index++
        }
        return out.toByteArray()
    }
}
