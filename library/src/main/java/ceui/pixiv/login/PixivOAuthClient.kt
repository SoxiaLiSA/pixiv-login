package ceui.pixiv.login

import android.content.Intent
import android.net.Uri
import ceui.pixiv.login.internal.OAuthApi
import ceui.pixiv.login.internal.RawTokenResponse
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.kotlinx.serialization.asConverterFactory
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * Pixiv OAuth 2.0 client for authorization-code exchange and token refresh.
 *
 * One instance per [PixivOAuthConfig] — each instance carries its own
 * [OkHttpClient] and Retrofit service, isolated from the app's
 * authenticated HTTP stack. This isolation is deliberate:
 *
 * - **No auth interceptor.** Adding a bearer-token interceptor to the
 *   OAuth client would create a chicken-and-egg loop when the token
 *   is the thing being obtained.
 * - **No authenticator.** Token-refresh calls must not re-enter the
 *   refresh lock held by the caller's own [okhttp3.Authenticator].
 * - **Separate connection pool.** Keeps the OAuth handshake off the
 *   connection pool shared by high-throughput API calls, so a slow
 *   token endpoint cannot starve image downloads.
 *
 * ## PKCE lifecycle
 *
 * [startLogin] generates a PKCE pair internally and caches the verifier
 * so the caller never touches it. [handleCallback] / [tryHandleCallback]
 * consumes the cached verifier and clears it. If the app process dies
 * between the two calls (rare — the Chrome Tab round-trip typically
 * takes seconds), the cached verifier is lost and [handleCallback]
 * returns [PixivOAuthResult.Failure]; the user simply retries login.
 *
 * For callers that need to survive process death (e.g. persist the
 * verifier in MMKV), the lower-level [buildLoginUrl] + [exchangeCode]
 * pair accepts an explicit verifier.
 *
 * ## Thread safety
 *
 * All public methods are safe to call from any thread.
 *
 * [startLogin] and [buildLoginUrl] are non-blocking and return
 * immediately. [tryHandleCallback], [handleCallback], [exchangeCode],
 * and [refreshToken] perform **synchronous blocking I/O** — call them
 * from a background thread or inside `withContext(Dispatchers.IO)`.
 * They are synchronous by design so they can be used both from
 * coroutines and from OkHttp's synchronous [okhttp3.Authenticator]
 * callback without requiring `runBlocking`.
 *
 * The internal PKCE cache ([pendingVerifier]) uses a single `@Volatile`
 * field. This is safe under the assumption that only **one login flow
 * is in progress at a time** — the normal case for interactive login.
 * Concurrent [startLogin] calls race on the write, and the last writer
 * wins; this is acceptable because the user can only be on one login
 * page at once.
 *
 * ## Lifecycle
 *
 * This class is designed to be held as a long-lived singleton (e.g.
 * in your `Application` or DI graph). The internal [OkHttpClient] is
 * created once and reused for all requests. There is no `close()`
 * method — the client is lightweight and safe to abandon; the
 * underlying connection pool will idle-close on its own.
 *
 * ## Typical usage
 *
 * ```kotlin
 * val client = PixivOAuthClient(PixivOAuthConfig.PIXIV_ANDROID)
 *
 * // 1. Open the login URL in a Chrome Custom Tab
 * val url = client.startLogin()
 * CustomTabsIntent.Builder().build().launchUrl(context, url.toUri())
 *
 * // 2. Handle callback in both onCreate and onNewIntent
 * fun handleIntent(intent: Intent?) {
 *     val result = client.tryHandleCallback(intent) ?: return
 *     result.onSuccess { save(it.accessToken, it.refreshToken) }
 * }
 *
 * // 3. Refresh when the access token expires
 * client.refreshToken(savedRefreshToken)
 * ```
 *
 * The caller must register an intent-filter for
 * [PixivOAuthConfig.callbackScheme] in AndroidManifest.xml so the OS
 * routes the OAuth redirect back to the app.
 *
 * @param config     identifies which Pixiv product and credentials to use.
 * @param baseClient optional [OkHttpClient] to derive from. The client
 *                   calls [OkHttpClient.newBuilder] on it and applies
 *                   timeouts, so the caller's interceptors (Chucker,
 *                   custom DNS, etc.) are inherited without mutation.
 *                   Pass `null` (the default) to create a standalone
 *                   client with no shared interceptors.
 * @param logHttp    enable HTTP body-level logging. Useful during
 *                   development; **disable in production** to avoid
 *                   leaking tokens and secrets to logcat.
 */
class PixivOAuthClient(
    val config: PixivOAuthConfig,
    baseClient: OkHttpClient? = null,
    logHttp: Boolean = false,
) {

    private val json = Json {
        ignoreUnknownKeys = true
        coerceInputValues = true
    }

    private val httpClient: OkHttpClient = (baseClient?.newBuilder() ?: OkHttpClient.Builder())
        .connectTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .readTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .writeTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .apply {
            if (logHttp) {
                addInterceptor(
                    HttpLoggingInterceptor().apply {
                        level = HttpLoggingInterceptor.Level.BODY
                    },
                )
            }
        }
        .build()

    private val api: OAuthApi = Retrofit.Builder()
        .baseUrl(config.oauthBaseUrl)
        .client(httpClient)
        .addConverterFactory(json.asConverterFactory("application/json".toMediaType()))
        .build()
        .create(OAuthApi::class.java)

    /**
     * Cached PKCE verifier from the most recent [startLogin] call.
     *
     * Written by [startLogin], consumed and cleared by [handleCallback].
     * `@Volatile` is sufficient because transitions are single-writer
     * (only one login flow at a time) and readers tolerate a brief
     * stale `null` (it just means "no login in progress").
     */
    @Volatile
    private var pendingVerifier: String? = null

    // ── High-level API ──────────────────────────────────────────────

    /**
     * Start a login flow: generate PKCE, cache the verifier, and return
     * the login URL to open in a Chrome Custom Tab or WebView.
     *
     * After the user authenticates, the server redirects to
     * `{callbackScheme}://account/login?code=…`. Intercept that redirect
     * via an intent-filter on [PixivOAuthConfig.callbackScheme] and pass
     * the received [Intent] to [tryHandleCallback].
     *
     * Calling [startLogin] again before [tryHandleCallback] discards the
     * previous PKCE pair — only the most recent login flow is valid.
     *
     * @return full login URL ready to open in a browser.
     */
    fun startLogin(): String {
        val pkce = PkceUtil.generate()
        pendingVerifier = pkce.verifier
        return buildLoginUrl(pkce.challenge)
    }

    /**
     * Check whether [uri] is an OAuth callback for this client.
     *
     * Matches when the URI scheme equals [PixivOAuthConfig.callbackScheme]
     * (e.g. `pixiv`, `pixiv-manga`). Does **not** validate host or path
     * — the server owns the redirect shape, and different Pixiv products
     * may use different paths.
     */
    fun isOAuthCallback(uri: Uri): Boolean {
        return uri.scheme == config.callbackScheme
    }

    /**
     * If [intent] carries an OAuth callback, exchange the code for tokens
     * and return the result. Otherwise return `null`.
     *
     * Designed to be called from **both** `onCreate` and `onNewIntent` —
     * one method covers both cold-start and warm-start:
     *
     * ```kotlin
     * private fun handleIntent(intent: Intent?) {
     *     val result = client.tryHandleCallback(intent) ?: return
     *     result.onSuccess { save(it.accessToken) }
     * }
     *
     * override fun onCreate(savedInstanceState: Bundle?) {
     *     super.onCreate(savedInstanceState)
     *     handleIntent(intent)
     * }
     *
     * override fun onNewIntent(intent: Intent) {
     *     super.onNewIntent(intent)
     *     handleIntent(intent)
     * }
     * ```
     *
     * **Blocking I/O** — call from a background thread. The `null`-return
     * path (non-OAuth intent) is non-blocking and safe on the main thread.
     *
     * @param intent the incoming intent (may be `null`, may carry a
     *               non-OAuth URI, or may carry the callback).
     * @return [PixivOAuthResult] if this was a callback intent,
     *         `null` if the intent is unrelated to OAuth.
     */
    fun tryHandleCallback(intent: Intent?): PixivOAuthResult? {
        val uri = intent?.data ?: return null
        if (!isOAuthCallback(uri)) return null
        return handleCallback(uri)
    }

    /**
     * Complete the login flow by extracting the authorization code from
     * the callback [uri] and exchanging it for tokens.
     *
     * **Blocking I/O** — call from a background thread.
     *
     * The [uri] is the full callback URI received via intent-filter
     * (e.g. `pixiv-manga://account/login?code=xxx&via=login`). The
     * library extracts the `code` query parameter internally — the
     * caller never needs to parse it.
     *
     * On success the cached PKCE verifier is cleared; on failure it is
     * preserved so a retry is possible (though Pixiv codes are
     * single-use — a retry would need a fresh [startLogin]).
     *
     * @param uri the full callback URI from `intent.data`.
     * @return [PixivOAuthResult.Success] with tokens, or
     *         [PixivOAuthResult.Failure] if the code is missing, the
     *         verifier is missing (process died), or the server rejected
     *         the exchange.
     */
    fun handleCallback(uri: Uri): PixivOAuthResult {
        val code = uri.getQueryParameter("code")
            ?: return PixivOAuthResult.Failure(
                httpCode = null,
                message = "No 'code' query parameter in callback URI: $uri",
            )
        val verifier = pendingVerifier
            ?: return PixivOAuthResult.Failure(
                httpCode = null,
                message = "No pending PKCE verifier — did the process restart " +
                    "between startLogin() and handleCallback()? Call startLogin() again.",
            )
        val result = exchangeCode(code, verifier)
        if (result.isSuccess) pendingVerifier = null
        return result
    }

    // ── Low-level API ───────────────────────────────────────────────

    /**
     * Build the login URL from an explicit [codeChallenge].
     *
     * Prefer [startLogin] unless you are managing PKCE persistence
     * yourself (e.g. surviving process death via MMKV).
     *
     * The [codeChallenge] is produced by [PkceUtil.generate] and is
     * already URL-safe Base64 — no additional encoding is applied.
     */
    fun buildLoginUrl(codeChallenge: String): String = buildString {
        append(config.loginUrl)
        append("?code_challenge=").append(codeChallenge)
        append("&code_challenge_method=S256")
        append("&client=").append(config.clientParam)
    }

    /**
     * Exchange an authorization code with an explicit PKCE verifier.
     *
     * Prefer [handleCallback] / [tryHandleCallback] unless you are
     * managing PKCE persistence yourself.
     *
     * **Blocking I/O** — call from a background thread.
     *
     * @param code         authorization code from the callback URI.
     * @param codeVerifier the [PkcePair.verifier] used to build the
     *                     login URL. The server verifies
     *                     `SHA-256(codeVerifier) == challenge`.
     */
    fun exchangeCode(code: String, codeVerifier: String): PixivOAuthResult {
        return executeTokenRequest(
            grantType = GRANT_TYPE_AUTH_CODE,
            code = code,
            codeVerifier = codeVerifier,
            redirectUri = config.redirectUri,
        )
    }

    /**
     * Obtain a new access token using a previously issued refresh token.
     *
     * **Blocking I/O** — call from a background thread.
     *
     * The returned [PixivOAuthResponse] includes a **new** refresh token;
     * the old one is invalidated. Callers must persist the new refresh
     * token and discard the old one.
     *
     * @param refreshToken the refresh token obtained from a prior
     *                     [handleCallback], [exchangeCode], or
     *                     [refreshToken] call.
     * @return [PixivOAuthResult.Success] with fresh tokens, or
     *         [PixivOAuthResult.Failure] if the refresh token is expired
     *         or revoked (typically HTTP 400).
     */
    fun refreshToken(refreshToken: String): PixivOAuthResult {
        return executeTokenRequest(
            grantType = GRANT_TYPE_REFRESH_TOKEN,
            refreshToken = refreshToken,
        )
    }

    // ── Internals ───────────────────────────────────────────────────

    private fun executeTokenRequest(
        grantType: String,
        code: String? = null,
        codeVerifier: String? = null,
        refreshToken: String? = null,
        redirectUri: String? = null,
    ): PixivOAuthResult {
        return try {
            val response = api.token(
                url = config.tokenEndpointPath,
                clientId = config.clientId,
                clientSecret = config.clientSecret,
                grantType = grantType,
                code = code,
                codeVerifier = codeVerifier,
                refreshToken = refreshToken,
                redirectUri = redirectUri,
            ).execute()

            val body = response.body()
            if (response.isSuccessful && body != null) {
                PixivOAuthResult.Success(body.toPublic())
            } else {
                PixivOAuthResult.Failure(
                    httpCode = response.code(),
                    message = response.errorBody()?.string() ?: "HTTP ${response.code()}",
                )
            }
        } catch (e: IOException) {
            PixivOAuthResult.Failure(
                httpCode = null,
                message = e.message ?: "Network error",
                cause = e,
            )
        } catch (e: Exception) {
            PixivOAuthResult.Failure(
                httpCode = null,
                message = e.message ?: "Unexpected error",
                cause = e,
            )
        }
    }

    private companion object {
        private const val TIMEOUT_SECONDS = 15L
        private const val GRANT_TYPE_AUTH_CODE = "authorization_code"
        private const val GRANT_TYPE_REFRESH_TOKEN = "refresh_token"
    }
}

// ── Wire → Public mapping ───────────────────────────────────────────

internal fun RawTokenResponse.toPublic() = PixivOAuthResponse(
    accessToken = access_token,
    refreshToken = refresh_token,
    expiresIn = expires_in,
    tokenType = token_type,
    scope = scope,
    user = user?.let {
        PixivOAuthUser(id = it.id, name = it.name, account = it.account)
    },
)
