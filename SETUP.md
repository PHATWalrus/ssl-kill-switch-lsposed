# Setup & Build Guide

## Requirements

### Device
- Android 8.0+ (API 26+)
- Magisk v24+ (or KernelSU)
- LSPosed v1.9.0+ installed via Magisk module
- Root access (required only for iptables proxy redirect feature)

### Build environment
- Android Studio Hedgehog (2023.1) or newer
- Android SDK 34
- Android NDK r25+ (r27 recommended)
- CMake 3.22+
- Java 17
- Gradle 8.x (via wrapper — no manual install needed)

## Build steps

### 1. Clone / open the project
```bash
git clone <this-repo>
cd ssl-kill-switch-lsposed
```

Open in Android Studio: **File → Open** → select the project root.

### 2. Sync Gradle
Android Studio will auto-sync. If it fails:
```bash
./gradlew dependencies
```

If JitPack fails to resolve `XposedBridge`, download the API JAR manually:
```
https://github.com/rovo89/XposedBridge/releases/download/art/XposedBridgeApi-89.jar
```
Place it at `app/libs/XposedBridgeApi-89.jar`, then in `app/build.gradle.kts` replace the JitPack dependency with:
```kotlin
compileOnly(files("libs/XposedBridgeApi-89.jar"))
```

### 3. Configure NDK path
In `local.properties` (create if missing):
```properties
sdk.dir=/path/to/Android/Sdk
ndk.dir=/path/to/Android/Sdk/ndk/27.x.x
```
Or set in Android Studio: **File → Project Structure → SDK Location**.

### 4. Build APK
```bash
./gradlew assembleDebug
# APK output: app/build/outputs/apk/debug/app-debug.apk
```

For release (sign with your keystore):
```bash
./gradlew assembleRelease
```

### 5. Install on device
```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

### 6. Activate in LSPosed
1. Open LSPosed Manager
2. Tap **Modules** → find **SSL Kill Switch**
3. Enable the module
4. Under **Scope**, add the target apps (or leave empty to configure via the module UI)
5. **Force stop** the target app to reload hooks

### 7. Configure via module UI
Open **SSL Kill Switch** app:
- **Apps tab**: toggle per-app SSL bypass, add domain filters
- **Proxy tab**: enter proxy host/port, enable iptables redirect

### 8. Proxy setup (optional)

#### Burp Suite
1. Listener: `0.0.0.0:8080` (or any port), Invisible Proxy mode on
2. In the module: set host = your machine IP, port = 8080
3. Tap **Apply iptables rules**
4. Import Burp CA to device trust store (Settings → Security → Install certificate)

#### mitmproxy
```bash
mitmproxy --mode transparent -p 8080
```
Same iptables config as above.

#### iptables rules applied by the module
```bash
# Per-UID TCP redirect to proxy (applied for each selected app)
iptables -t nat -A OUTPUT -m owner --uid-owner <uid> -p tcp -j DNAT \
  --to-destination <proxy_host>:<proxy_port>

# Flush on disable
iptables -t nat -D OUTPUT -m owner --uid-owner <uid> -p tcp -j DNAT \
  --to-destination <proxy_host>:<proxy_port>
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Module not loading | Check LSPosed scope includes target app; force-stop app |
| Java hooks not working | Enable verbose logging in LSPosed; check logcat `ssl_kill_switch` tag |
| Native hooks not working | Verify NDK build succeeded (`libssl_kill_switch.so` present in APK); check `arm64-v8a` ABI |
| Flutter app still pinning | The app may use certificate transparency or custom Dart HTTP; try iptables + mitmproxy transparent mode |
| iptables rules not applying | Ensure root access is granted to the module; check `su -c iptables -t nat -L OUTPUT` |
| Logcat errors `mprotect failed` | SELinux policy blocking memory permission changes; try `setenforce 0` (testing only) |
