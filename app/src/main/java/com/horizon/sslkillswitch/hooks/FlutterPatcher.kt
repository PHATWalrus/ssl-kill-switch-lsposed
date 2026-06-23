package com.horizon.sslkillswitch.hooks

import android.os.Build
import android.util.Log
import java.io.File
import java.io.RandomAccessFile
import java.util.zip.ZipFile

private const val TAG = "SSLKillSwitch"

/**
 * Kotlin-side Flutter/BoringSSL bypass via file patching.
 *
 * Strategy: scan libflutter.so bytes for ssl_verify_peer_cert prologue,
 * copy the file, overwrite the prologue with a return-0 stub, then load
 * the patched copy before the original is mapped.
 *
 * Handles both extracted libs (android:extractNativeLibs=true) and
 * APK-embedded libs (android:extractNativeLibs=false, default since AGP 4.2).
 */
object FlutterPatcher {

    private data class PatternByte(val value: Int, val mask: Int)

    // ── ssl_verify_peer_cert prologue patterns ────────────────────────────────

    private val PATTERNS_ARM64 = listOf(
        "F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? ?? 03 A9 ?? ?? ?? ?? 68 1A 40 F9",
        "F? 43 01 D1 FE 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 13 00 40 F9 F4 03 00 AA 68 1A 40 F9",
        "FF 43 01 D1 FE 67 01 A9 ?? ?? 06 94 ?? 7? 06 94 68 1A 40 F9 15 15 41 F9 B5 00 00 B4 B6 4A 40 F9",
        "FF C3 01 D1 FD 7B 01 A9 6A A1 0B 94 08 0A 80 52 48 00 00 39 1A 50 40 F9 DA 02 00 B4 48 03 40 F9"
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
    private val PATCH_ARM64  = byteArrayOf(0x00, 0x00, 0x80.toByte(), 0x52, 0xC0.toByte(), 0x03, 0x5F, 0xD6.toByte())
    private val PATCH_ARM32  = byteArrayOf(0x00, 0x20, 0x70, 0x47)
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

    // ── APK helpers ───────────────────────────────────────────────────────────

    // Maps Build.SUPPORTED_ABIS entry to APK lib directory name
    private fun abiToApkDir(abi: String): String = when {
        abi.contains("arm64")   -> "arm64-v8a"
        abi.contains("armeabi") -> "armeabi-v7a"
        abi.contains("x86_64")  -> "x86_64"
        abi.contains("x86")     -> "x86"
        else                    -> abi
    }

    // Returns all APK paths for the running application (base + splits)
    private fun allApkPaths(): List<String> {
        val at  = Class.forName("android.app.ActivityThread")
        val app = at.getMethod("currentApplication").invoke(null) ?: return emptyList()
        val ai  = app.javaClass.getMethod("getApplicationInfo").invoke(app) ?: return emptyList()
        val src    = ai.javaClass.getField("sourceDir").get(ai) as? String
        val splits = (ai.javaClass.getField("splitSourceDirs").get(ai) as? Array<*>)
            ?.filterIsInstance<String>() ?: emptyList()
        return listOfNotNull(src) + splits
    }

    /**
     * Scan all APKs (base + splits) for libflutter.so and return an APK-embedded path
     * ("path/base.apk!/lib/arm64-v8a/libflutter.so") pointing to the first match.
     * Tries ABIs in Build.SUPPORTED_ABIS order.
     */
    private fun scanApksForFlutter(): String? {
        val apks  = runCatching { allApkPaths() }.getOrElse { return null }
        val abis  = Build.SUPPORTED_ABIS.map(::abiToApkDir).distinct()
        for (apk in apks) {
            runCatching {
                ZipFile(apk).use { zip ->
                    for (dir in abis) {
                        val entry = zip.getEntry("lib/$dir/libflutter.so") ?: continue
                        val path  = "$apk!/lib/$dir/libflutter.so"
                        Log.i(TAG, "FlutterPatcher: found lib/$dir/libflutter.so in $apk (${entry.size} bytes)")
                        return path
                    }
                }
            }.onFailure { Log.d(TAG, "FlutterPatcher: APK scan $apk failed — ${it.message}") }
        }
        return null
    }

    /**
     * Extracts a lib from an APK-embedded path ("apk!/lib/arch/lib.so") to the
     * app's cache dir and returns the extracted file path. Returns null on failure.
     */
    private fun extractFromApk(apkEmbeddedPath: String, pkg: String): String? {
        val sep = apkEmbeddedPath.indexOf("!/")
        if (sep < 0) return null
        val apkPath   = apkEmbeddedPath.substring(0, sep)
        val entryPath = apkEmbeddedPath.substring(sep + 2)  // strip "!/"

        return runCatching {
            ZipFile(apkPath).use { zip ->
                val entry = zip.getEntry(entryPath) ?: run {
                    Log.e(TAG, "FlutterPatcher: entry $entryPath not in $apkPath")
                    return null
                }
                val out = File(getCacheDir(pkg), "libflutter_extracted.so")
                zip.getInputStream(entry).use { inp -> out.outputStream().use { inp.copyTo(it) } }
                Log.i(TAG, "FlutterPatcher: extracted $entryPath → ${out.absolutePath} (${out.length()} bytes)")
                out.absolutePath
            }
        }.getOrElse {
            Log.e(TAG, "FlutterPatcher: APK extraction failed: ${it.message}")
            null
        }
    }

    // ── Path resolution ───────────────────────────────────────────────────────

    /**
     * Resolve the on-disk (or APK-embedded) path of libflutter.so.
     * Returns a regular file path OR an APK-embedded path ("apk!/lib/arch/lib.so").
     * Callers must handle the APK case — patch() does this automatically.
     */
    fun findLibFlutterPath(cl: ClassLoader): String? {
        Log.d(TAG, "FlutterPatcher: findLibFlutterPath via ${cl.javaClass.name}")

        // Strategy 1: ClassLoader.findLibrary
        // Returns on-disk path for extractNativeLibs=true, or APK-embedded path for =false.
        runCatching {
            val path = cl.javaClass.getMethod("findLibrary", String::class.java)
                .invoke(cl, "flutter") as? String
            if (path != null) {
                val onDisk = File(path).exists()
                val inApk  = path.contains("!/")
                if (onDisk || inApk) {
                    Log.i(TAG, "FlutterPatcher: resolved via findLibrary → $path (onDisk=$onDisk, inApk=$inApk)")
                    return path
                }
                Log.d(TAG, "FlutterPatcher: findLibrary returned $path — not on disk, not APK path")
            } else {
                Log.d(TAG, "FlutterPatcher: findLibrary returned null")
            }
        }.onFailure { Log.d(TAG, "FlutterPatcher: findLibrary failed — ${it.message}") }

        // Strategy 2: nativeLibraryDir (extracted libs only)
        runCatching {
            val at  = Class.forName("android.app.ActivityThread")
            val app = at.getMethod("currentApplication").invoke(null) ?: return@runCatching
            val ai  = app.javaClass.getMethod("getApplicationInfo").invoke(app) ?: return@runCatching
            val dir = ai.javaClass.getField("nativeLibraryDir").get(ai) as? String ?: return@runCatching
            Log.d(TAG, "FlutterPatcher: nativeLibraryDir=$dir")
            val f = File(dir, "libflutter.so")
            if (f.exists()) {
                Log.i(TAG, "FlutterPatcher: resolved via nativeLibraryDir → ${f.absolutePath}")
                return f.absolutePath
            }
        }.onFailure { Log.d(TAG, "FlutterPatcher: nativeLibraryDir strategy failed — ${it.message}") }

        // Strategy 3: Direct APK scan (base + split APKs).
        // Required when extractNativeLibs=false and findLibrary returns null.
        runCatching {
            val apkPath = scanApksForFlutter()
            if (apkPath != null) {
                Log.i(TAG, "FlutterPatcher: resolved via APK scan → $apkPath")
                return apkPath
            }
        }.onFailure { Log.d(TAG, "FlutterPatcher: APK scan strategy failed — ${it.message}") }

        Log.e(TAG, "FlutterPatcher: all path resolution strategies exhausted — libflutter.so not found")
        return null
    }

    // ── Cache dir ─────────────────────────────────────────────────────────────

    private fun getCacheDir(pkg: String): File {
        runCatching {
            val at  = Class.forName("android.app.ActivityThread")
            val app = at.getMethod("currentApplication").invoke(null)
            val dir = app?.javaClass?.getMethod("getCacheDir")?.invoke(app) as? File
            if (dir != null) {
                Log.d(TAG, "FlutterPatcher: cache dir via Context.getCacheDir → ${dir.absolutePath}")
                return dir
            }
        }.onFailure { Log.d(TAG, "FlutterPatcher: getCacheDir reflection failed — ${it.message}") }
        val fallback = File("/data/data/$pkg/cache").also { it.mkdirs() }
        Log.d(TAG, "FlutterPatcher: cache dir fallback → ${fallback.absolutePath}")
        return fallback
    }

    // ── Patched lib loader ────────────────────────────────────────────────────

    /**
     * Load the patched libflutter.so using multiple strategies in priority order.
     * The caller ClassLoader is needed so the native lib resolves symbols in the
     * correct namespace — System.load() alone causes ClassLoader mismatch crashes.
     */
    fun loadPatched(patchedPath: String, cl: ClassLoader, pkg: String): Boolean {
        val runtime = Runtime.getRuntime()
        val rClass  = runtime.javaClass

        // Strategy 1: Runtime.load0(Class, String) — pass Flutter's own class as caller
        runCatching {
            val callerClass = runCatching {
                cl.loadClass("io.flutter.embedding.engine.FlutterJNI")
            }.getOrNull()
            if (callerClass != null) {
                val m = rClass.declaredMethods.firstOrNull {
                    it.name == "load0" && it.parameterTypes.size == 2 &&
                        it.parameterTypes[0] == Class::class.java &&
                        it.parameterTypes[1] == String::class.java
                }
                if (m != null) {
                    m.isAccessible = true
                    m.invoke(runtime, callerClass, patchedPath)
                    Log.i(TAG, "FlutterPatcher: [$pkg] loaded via Runtime.load0(Class, String)")
                    return true
                }
            }
        }.onFailure { Log.d(TAG, "FlutterPatcher: [$pkg] load0(Class) failed: ${it.message}") }

        // Strategy 2: Runtime.load0(ClassLoader, String)
        runCatching {
            val m = rClass.declaredMethods.firstOrNull {
                it.name == "load0" && it.parameterTypes.size == 2 &&
                    it.parameterTypes[0] == ClassLoader::class.java &&
                    it.parameterTypes[1] == String::class.java
            }
            if (m != null) {
                m.isAccessible = true
                m.invoke(runtime, cl, patchedPath)
                Log.i(TAG, "FlutterPatcher: [$pkg] loaded via Runtime.load0(ClassLoader, String)")
                return true
            }
        }.onFailure { Log.d(TAG, "FlutterPatcher: [$pkg] load0(ClassLoader) failed: ${it.message}") }

        // Strategy 3: Runtime.load(String, ClassLoader)
        runCatching {
            val m = rClass.declaredMethods.firstOrNull {
                it.name == "load" && it.parameterTypes.size == 2 &&
                    it.parameterTypes[0] == String::class.java &&
                    it.parameterTypes[1] == ClassLoader::class.java
            }
            if (m != null) {
                m.isAccessible = true
                m.invoke(runtime, patchedPath, cl)
                Log.i(TAG, "FlutterPatcher: [$pkg] loaded via Runtime.load(String, ClassLoader)")
                return true
            }
        }.onFailure { Log.d(TAG, "FlutterPatcher: [$pkg] load(String,CL) failed: ${it.message}") }

        // Strategy 4: Runtime.nativeLoad(String, ClassLoader)
        runCatching {
            val m = rClass.declaredMethods.firstOrNull {
                it.name == "nativeLoad" && it.parameterTypes.size == 2 &&
                    it.parameterTypes[0] == String::class.java &&
                    it.parameterTypes[1] == ClassLoader::class.java
            }
            if (m != null) {
                m.isAccessible = true
                val err = m.invoke(runtime, patchedPath, cl) as? String
                if (err == null) {
                    Log.i(TAG, "FlutterPatcher: [$pkg] loaded via Runtime.nativeLoad")
                    return true
                }
                Log.w(TAG, "FlutterPatcher: [$pkg] nativeLoad error: $err")
            }
        }.onFailure { Log.d(TAG, "FlutterPatcher: [$pkg] nativeLoad failed: ${it.message}") }

        // Strategy 5: System.load — last resort, may cause ClassLoader mismatch
        return runCatching {
            System.load(patchedPath)
            Log.i(TAG, "FlutterPatcher: [$pkg] loaded via System.load (last resort)")
            true
        }.getOrElse {
            Log.e(TAG, "FlutterPatcher: [$pkg] System.load failed: ${it.message}")
            false
        }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Copy/extract libflutter.so, patch ssl_verify_peer_cert to return 0, return patched path.
     * Accepts both on-disk paths and APK-embedded paths ("apk!/lib/arch/lib.so").
     * Returns null if the pattern didn't match or file ops failed.
     */
    fun patch(libFlutterPath: String, pkg: String): String? {
        val arch = detectArch()
        Log.i(TAG, "FlutterPatcher: patch() src=$libFlutterPath pkg=$pkg arch=$arch")

        // For APK-embedded paths extract the lib to disk first; patch() needs a real File.
        val srcPath = if (libFlutterPath.contains("!/")) {
            extractFromApk(libFlutterPath, pkg) ?: run {
                Log.e(TAG, "FlutterPatcher: APK extraction failed for $libFlutterPath")
                return null
            }
        } else {
            libFlutterPath
        }

        val (patterns, patchBytes, thumbOffset) = when (arch) {
            "arm64" -> Triple(PATTERNS_ARM64,  PATCH_ARM64,  0)
            "arm"   -> Triple(PATTERNS_ARM32,  PATCH_ARM32,  1)
            "x64"   -> Triple(PATTERNS_X64,    PATCH_X86X64, 0)
            "x86"   -> Triple(PATTERNS_X86,    PATCH_X86X64, 0)
            else    -> { Log.e(TAG, "FlutterPatcher: unsupported arch $arch"); return null }
        }
        Log.d(TAG, "FlutterPatcher: ${patterns.size} pattern(s) arch=$arch patch=${patchBytes.size}B thumbOffset=$thumbOffset")

        val src = File(srcPath)
        if (!src.exists()) { Log.e(TAG, "FlutterPatcher: $srcPath not found"); return null }

        val data = runCatching { src.readBytes() }.getOrElse {
            Log.e(TAG, "FlutterPatcher: read failed — ${it.message}"); return null
        }
        Log.d(TAG, "FlutterPatcher: read ${data.size} bytes from $srcPath")

        for ((idx, patStr) in patterns.withIndex()) {
            Log.d(TAG, "FlutterPatcher: trying pattern[$idx]: ${patStr.take(48)}…")
            val compiled    = parsePattern(patStr)
            val offset      = scanPattern(data, compiled)
            if (offset < 0) { Log.d(TAG, "FlutterPatcher: pattern[$idx] — no match"); continue }

            val patchOffset = offset + thumbOffset
            Log.i(TAG, "FlutterPatcher: matched pattern[$idx] @ 0x${patchOffset.toString(16)}")

            // Write to a distinct output file so the extracted file stays reusable
            val out = File(getCacheDir(pkg), "libflutter_patched.so")
            Log.d(TAG, "FlutterPatcher: copying $srcPath → ${out.absolutePath}")
            runCatching { src.copyTo(out, overwrite = true) }.getOrElse {
                Log.e(TAG, "FlutterPatcher: copy failed — ${it.message}"); return null
            }

            Log.d(TAG, "FlutterPatcher: writing ${patchBytes.size}B stub at 0x${patchOffset.toString(16)}")
            runCatching {
                RandomAccessFile(out, "rw").use { raf ->
                    raf.seek(patchOffset.toLong())
                    raf.write(patchBytes)
                    // verify read-back — catch silent write corruption
                    val check = ByteArray(patchBytes.size)
                    raf.seek(patchOffset.toLong())
                    raf.readFully(check)
                    if (!check.contentEquals(patchBytes)) {
                        throw IllegalStateException("verify mismatch @ 0x${patchOffset.toString(16)}")
                    }
                }
            }.getOrElse {
                Log.e(TAG, "FlutterPatcher: write failed — ${it.message}")
                out.delete(); return null
            }

            Log.i(TAG, "FlutterPatcher: patch complete → ${out.absolutePath}")
            return out.absolutePath
        }

        Log.e(TAG, "FlutterPatcher: all ${patterns.size} patterns missed for arch=$arch — Flutter version not covered")
        return null
    }
}
