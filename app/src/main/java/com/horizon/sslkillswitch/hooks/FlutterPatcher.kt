package com.horizon.sslkillswitch.hooks

import android.util.Log
import java.io.File
import java.io.RandomAccessFile

private const val TAG = "SSLKillSwitch"

/**
 * Kotlin-side Flutter/BoringSSL bypass via file patching.
 *
 * Strategy: scan libflutter.so bytes for ssl_verify_peer_cert prologue,
 * copy the file, overwrite the prologue with a return-0 stub, then load
 * the patched copy via System.load() before the original is mapped.
 *
 * Patterns ported from SSLUnpinner (pccr10001) — same nibble-wildcard format.
 */
object FlutterPatcher {

    private data class PatternByte(val value: Int, val mask: Int)

    // ── ssl_verify_peer_cert prologue patterns ────────────────────────────────

    private val PATTERNS_ARM64 = listOf(
        "F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? ?? 03 A9 ?? ?? ?? ?? 68 1A 40 F9",
        "F? 43 01 D1 FE 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 13 00 40 F9 F4 03 00 AA 68 1A 40 F9",
        "FF 43 01 D1 FE 67 01 A9 ?? ?? 06 94 ?? 7? 06 94 68 1A 40 F9 15 15 41 F9 B5 00 00 B4 B6 4A 40 F9",
        "FF C3 01 D1 FD 7B 01 A9 6A A1 0B 94 08 0A 80 52 48 00 00 39 1A 50 40 F9 DA 02 00 B4 48 03 40 F9",
    )
    private val PATTERNS_ARM32 = listOf(
        "2D E9 F? 4? D0 F8 00 80 81 46 D8 F8 18 00 D0 F8",
    )
    private val PATTERNS_X64 = listOf(
        "55 41 57 41 56 41 55 41 54 53 50 49 89 f? 4? 8b ?? 4? 8b 4? 30 4c 8b ?? ?? 0? 00 00 4d 85 ?? 74 1? 4d 8b",
        "55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FF 48 8B 1F 48 8B 43 30 4C 8B A0 28 02 00 00 4D 85 E4 74",
        "55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FE 4C 8B 27 49 8B 44 24 30 48 8B 98 D0 01 00 00 48 85 DB",
    )
    private val PATTERNS_X86 = listOf(
        "55 89 E5 53 57 56 83 E4 F0 83 EC 20 E8 00 00 00 00 5B 81 C3 2B 79 66 00 8B 7D 08 8B 17 8B 42 18 8B 80 88 01",
    )

    // ── Return-zero stubs ─────────────────────────────────────────────────────
    // ARM64: MOV W0, #0 ; RET
    private val PATCH_ARM64  = byteArrayOf(0x00, 0x00, 0x80.toByte(), 0x52, 0xC0.toByte(), 0x03, 0x5F, 0xD6.toByte())
    // ARM32: MOVS R0, #0 ; BX LR  (Thumb-2, applied at offset+1)
    private val PATCH_ARM32  = byteArrayOf(0x00, 0x20, 0x70, 0x47)
    // x86 / x64: XOR EAX, EAX ; RET
    private val PATCH_X86X64 = byteArrayOf(0x31, 0xC0.toByte(), 0xC3.toByte())

    // ── Pattern helpers ───────────────────────────────────────────────────────

    private fun parsePattern(hex: String): List<PatternByte> =
        hex.trim().split(" ").map { token ->
            val hiWild = token[0] == '?'
            val loWild = token[1] == '?'
            val hi = if (hiWild) 0 else token[0].digitToInt(16)
            val lo = if (loWild) 0 else token[1].digitToInt(16)
            PatternByte(
                value = (hi shl 4) or lo,
                mask  = (if (hiWild) 0x00 else 0xF0) or (if (loWild) 0x00 else 0x0F)
            )
        }

    private fun scanPattern(data: ByteArray, pattern: List<PatternByte>): Int {
        outer@ for (i in 0..data.size - pattern.size) {
            for (j in pattern.indices) {
                val b = data[i + j].toInt() and 0xFF
                if (b and pattern[j].mask != pattern[j].value and pattern[j].mask) continue@outer
            }
            return i
        }
        return -1
    }

    private fun detectArch(): String {
        val abi = System.getProperty("os.arch") ?: ""
        val arch = when {
            abi.contains("aarch64") || abi.contains("arm64") -> "arm64"
            abi.contains("arm")                              -> "arm"
            abi.contains("x86_64") || abi.contains("amd64") -> "x64"
            abi.contains("x86") || abi.contains("i686")     -> "x86"
            else                                             -> abi
        }
        Log.d(TAG, "FlutterPatcher: detectArch os.arch=$abi → $arch")
        return arch
    }

    // ── Path resolution ───────────────────────────────────────────────────────

    /** Resolve the on-disk path of libflutter.so using the target app's ClassLoader. */
    fun findLibFlutterPath(cl: ClassLoader): String? {
        Log.d(TAG, "FlutterPatcher: findLibFlutterPath via ${cl.javaClass.name}")

        // Strategy 1: ClassLoader.findLibrary (PathClassLoader exposes this)
        runCatching {
            val path = cl.javaClass.getMethod("findLibrary", String::class.java)
                .invoke(cl, "flutter") as? String
            if (path != null && File(path).exists()) {
                Log.i(TAG, "FlutterPatcher: libflutter.so resolved via findLibrary → $path")
                return path
            }
            Log.d(TAG, "FlutterPatcher: findLibrary returned ${path ?: "null"} — trying next strategy")
        }.onFailure {
            Log.d(TAG, "FlutterPatcher: findLibrary strategy failed — ${it.message}")
        }

        // Strategy 2: ApplicationInfo.nativeLibraryDir via ActivityThread
        runCatching {
            val at  = Class.forName("android.app.ActivityThread")
            val app = at.getMethod("currentApplication").invoke(null) ?: return@runCatching
            val ai  = app.javaClass.getMethod("getApplicationInfo").invoke(app) ?: return@runCatching
            val dir = ai.javaClass.getField("nativeLibraryDir").get(ai) as? String ?: return@runCatching
            Log.d(TAG, "FlutterPatcher: nativeLibraryDir=$dir")
            val f = File(dir, "libflutter.so")
            if (f.exists()) {
                Log.i(TAG, "FlutterPatcher: libflutter.so resolved via nativeLibraryDir → ${f.absolutePath}")
                return f.absolutePath
            }
            Log.d(TAG, "FlutterPatcher: libflutter.so not found in nativeLibraryDir")
        }.onFailure {
            Log.d(TAG, "FlutterPatcher: nativeLibraryDir strategy failed — ${it.message}")
        }

        Log.e(TAG, "FlutterPatcher: all path resolution strategies exhausted — libflutter.so not found")
        return null
    }

    private fun getCacheDir(pkg: String): File {
        runCatching {
            val at  = Class.forName("android.app.ActivityThread")
            val app = at.getMethod("currentApplication").invoke(null)
            val dir = app?.javaClass?.getMethod("getCacheDir")?.invoke(app) as? File
            if (dir != null) {
                Log.d(TAG, "FlutterPatcher: cache dir via Context.getCacheDir → ${dir.absolutePath}")
                return dir
            }
        }.onFailure {
            Log.d(TAG, "FlutterPatcher: getCacheDir reflection failed — ${it.message}")
        }
        val fallback = File("/data/data/$pkg/cache").also { it.mkdirs() }
        Log.d(TAG, "FlutterPatcher: cache dir fallback → ${fallback.absolutePath}")
        return fallback
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Copy libflutter.so, patch ssl_verify_peer_cert to return 0, return patched path.
     * Returns null if no pattern matched or file ops failed.
     */
    fun patch(libFlutterPath: String, pkg: String): String? {
        val arch = detectArch()
        Log.i(TAG, "FlutterPatcher: patch() src=$libFlutterPath pkg=$pkg arch=$arch")

        val (patterns, patchBytes, thumbOffset) = when (arch) {
            "arm64" -> Triple(PATTERNS_ARM64,  PATCH_ARM64,  0)
            "arm"   -> Triple(PATTERNS_ARM32,  PATCH_ARM32,  1)
            "x64"   -> Triple(PATTERNS_X64,    PATCH_X86X64, 0)
            "x86"   -> Triple(PATTERNS_X86,    PATCH_X86X64, 0)
            else    -> { Log.e(TAG, "FlutterPatcher: unsupported arch $arch"); return null }
        }
        Log.d(TAG, "FlutterPatcher: using ${patterns.size} pattern(s) for $arch, patch=${patchBytes.size}B, thumbOffset=$thumbOffset")

        val src = File(libFlutterPath)
        if (!src.exists()) { Log.e(TAG, "FlutterPatcher: $libFlutterPath not found"); return null }

        val data = runCatching { src.readBytes() }.getOrElse {
            Log.e(TAG, "FlutterPatcher: read failed — ${it.message}"); return null
        }
        Log.d(TAG, "FlutterPatcher: read ${data.size} bytes from $libFlutterPath")

        for ((idx, patStr) in patterns.withIndex()) {
            Log.d(TAG, "FlutterPatcher: trying pattern[$idx]: ${patStr.take(48)}…")
            val compiled = parsePattern(patStr)
            val offset   = scanPattern(data, compiled)
            if (offset < 0) {
                Log.d(TAG, "FlutterPatcher: pattern[$idx] — no match")
                continue
            }

            val patchOffset = offset + thumbOffset
            Log.i(TAG, "FlutterPatcher: ssl_verify_peer_cert matched pattern[$idx] @ file offset 0x${patchOffset.toString(16)}")

            val out = File(getCacheDir(pkg), "libflutter_patched.so")
            Log.d(TAG, "FlutterPatcher: copying $libFlutterPath → ${out.absolutePath}")
            runCatching { src.copyTo(out, overwrite = true) }.getOrElse {
                Log.e(TAG, "FlutterPatcher: copy failed — ${it.message}"); return null
            }

            Log.d(TAG, "FlutterPatcher: writing ${patchBytes.size}B return-zero stub at 0x${patchOffset.toString(16)}")
            runCatching {
                RandomAccessFile(out, "rw").use { raf ->
                    raf.seek(patchOffset.toLong())
                    raf.write(patchBytes)
                }
            }.getOrElse {
                Log.e(TAG, "FlutterPatcher: write failed — ${it.message}")
                out.delete()
                return null
            }

            Log.i(TAG, "FlutterPatcher: patch complete → ${out.absolutePath}")
            return out.absolutePath
        }

        Log.e(TAG, "FlutterPatcher: all ${patterns.size} patterns missed for arch=$arch — libflutter.so version not covered")
        return null
    }
}
