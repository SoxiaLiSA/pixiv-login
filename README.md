# pixiv-login

Android library for Pixiv OAuth 2.0 login (PKCE).  
One dependency, three steps, done.

[![](https://jitpack.io/v/SoxiaLiSA/pixiv-login.svg)](https://jitpack.io/#SoxiaLiSA/pixiv-login)

## Setup

### 1. Add dependency

**settings.gradle.kts**

```kotlin
dependencyResolutionManagement {
    repositories {
        maven("https://jitpack.io")
    }
}
```

**build.gradle.kts**

```kotlin
dependencies {
    implementation("com.github.SoxiaLiSA:pixiv-login:1.0.0")
}
```

### 2. Register callback scheme in AndroidManifest.xml

> **This step is critical.** Without it, the system cannot route the OAuth redirect back to your app.

Add an intent-filter to the Activity that will receive the login callback:

```xml
<activity
    android:name=".LoginActivity"
    android:launchMode="singleTask">

    <!-- Pixiv OAuth callback -->
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="pixiv" />
    </intent-filter>
</activity>
```

| Config | Scheme |
|---|---|
| `PixivOAuthConfig.PIXIV_ANDROID` | `pixiv` |
| `PixivOAuthConfig.PIXIV_COMIC` | `pixiv-manga` |

Using `PIXIV_COMIC`? Change `android:scheme` to `pixiv-manga`.

---

## Usage

### Kotlin (3 steps)

```kotlin
// ① Create client (singleton, keep it alive)
val client = PixivOAuthClient(PixivOAuthConfig.PIXIV_ANDROID)

// ② Start login — open the URL in Chrome Custom Tab
val url = client.startLogin()
CustomTabsIntent.Builder().build().launchUrl(context, url.toUri())

// ③ Handle callback — in your Activity
override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    handleIntent(intent)
}

override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    handleIntent(intent)
}

private fun handleIntent(intent: Intent?) {
    val result = client.tryHandleCallback(intent) ?: return
    when (result) {
        is PixivOAuthResult.Success -> {
            val accessToken  = result.response.accessToken
            val refreshToken = result.response.refreshToken
            // save tokens, navigate to main screen
        }
        is PixivOAuthResult.Failure -> {
            Log.e("Login", "Failed: ${result.message}")
        }
    }
}
```

> `tryHandleCallback` does blocking I/O. Call it on a background thread or use the suspend version:

```kotlin
lifecycleScope.launch {
    val result = client.tryHandleCallbackSuspend(intent) ?: return@launch
    result.onSuccess { save(it.accessToken, it.refreshToken) }
           .onFailure { Log.e("Login", it.message) }
}
```

### Refresh token

```kotlin
// The old refresh token is invalidated — always save the new one
val result = client.refreshToken(savedRefreshToken)
// or
val result = client.refreshTokenSuspend(savedRefreshToken)
```

### Check expiry

```kotlin
if (response.isExpired()) {
    // token expired, call refreshToken
}

// Refresh 60 seconds early to avoid edge cases
if (response.isExpired(marginMillis = 60_000)) {
    // almost expired
}
```

---

## Advanced

### Survive process death

The default in-memory verifier is lost if Android kills your app during login. To fix this, implement `VerifierStore`:

```kotlin
class MmkvVerifierStore(private val mmkv: MMKV) : VerifierStore {
    override fun save(verifier: String) = mmkv.encode("pkce_verifier", verifier)
    override fun load(): String? = mmkv.decodeString("pkce_verifier")
    override fun clear() = mmkv.removeValueForKey("pkce_verifier")
}

val client = PixivOAuthClient(
    config = PixivOAuthConfig.PIXIV_ANDROID,
    verifierStore = MmkvVerifierStore(mmkv),
)
```

### Debug HTTP logging

```kotlin
val client = PixivOAuthClient(
    config = PixivOAuthConfig.PIXIV_ANDROID,
    logHttp = true, // DO NOT enable in production
)
```

### Share your app's OkHttpClient

```kotlin
val client = PixivOAuthClient(
    config = PixivOAuthConfig.PIXIV_ANDROID,
    baseClient = yourOkHttpClient, // inherits your DNS, Chucker, etc.
)
```

---

## API at a glance

| Method | Description |
|---|---|
| `startLogin()` | Generate PKCE + return login URL |
| `tryHandleCallback(intent)` | Exchange code for tokens (if intent is a callback) |
| `refreshToken(token)` | Get new access token |
| `isExpired()` / `isExpired(margin)` | Check token expiry |
| `*Suspend` variants | Cancellation-aware coroutine versions |

## Requirements

- `minSdk 21`
- Kotlin or Java

## License

MIT
