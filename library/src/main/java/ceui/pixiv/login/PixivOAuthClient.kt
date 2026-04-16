package ceui.pixiv.login

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
 * ## Thread safety
 *
 * All public methods are safe to call from any thread. [exchangeCode]
 * and [refreshToken] perform **synchronous** blocking I/O — call them
 * from a background thread or inside `withContext(Dispatchers.IO)`.
 * They are synchronous by design so they can be used both from
 * coroutines and from OkHttp's synchronous [okhttp3.Authenticator]
 * callback without requiring `runBlocking`.
 *
 * ## Typical usage
 *
 * ```kotlin
 * val client = PixivOAuthClient(PixivOAuthConfig.PIXIV_ANDROID)
 *
 * // 1. Generate PKCE and open the login URL
 * val pkce = PkceUtil.generate()
 * val url  = client.buildLoginUrl(pkce.challenge)
 * // → open url in Chrome Custom Tab, persist pkce.verifier
 *
 * // 2. Receive the callback and exchange the code
 * val result = client.exchangeCode(code, savedVerifier)
 * result.onSuccess { response ->
 *     save(response.accessToken, response.refreshToken)
 * }
 *
 * // 3. Refresh when the access token expires
 * val refreshResult = client.refreshToken(savedRefreshToken)
 * ```
 *
 * @param config   identifies which Pixiv product and credentials to use.
 * @param logHttp  enable HTTP body-level logging. Useful during
 *                 development; disable in production to avoid leaking
 *                 tokens to logcat.
 */
class PixivOAuthClient(
    val config: PixivOAuthConfig,
    logHttp: Boolean = false,
) {

    private val json = Json {
        ignoreUnknownKeys = true
        coerceInputValues = true
    }

    private val httpClient: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .writeTimeout(15, TimeUnit.SECONDS)
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

    // ── Public API ──────────────────────────────────────────────────

    /**
     * Build the full login URL to open in a Chrome Custom Tab or WebView.
     *
     * The returned URL points to the product's login page with the PKCE
     * [codeChallenge] embedded. After the user authenticates, the server
     * redirects through the OAuth flow and eventually issues a callback
     * to a custom scheme (e.g. `pixiv://account/login?code=…`) that the
     * calling app intercepts via an intent-filter.
     *
     * @param codeChallenge the `S256` challenge from [PkceUtil.generate].
     */
    fun buildLoginUrl(codeChallenge: String): String = buildString {
        append(config.loginUrl)
        append("?code_challenge=").append(codeChallenge)
        append("&code_challenge_method=S256")
        append("&client=").append(config.clientParam)
    }

    /**
     * Exchange an authorization code for an access token and refresh token.
     *
     * **Blocking I/O** — call from a background thread.
     *
     * @param code         the authorization code extracted from the OAuth
     *                     callback URI's `code` query parameter.
     * @param codeVerifier the [PkcePair.verifier] that was generated
     *                     alongside the challenge used in [buildLoginUrl].
     *                     Must be the **exact same value** — the server
     *                     verifies `SHA-256(codeVerifier) == challenge`.
     * @return [PixivOAuthResult.Success] with tokens, or
     *         [PixivOAuthResult.Failure] with diagnostic context.
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
     *                     [exchangeCode] or [refreshToken] call.
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
