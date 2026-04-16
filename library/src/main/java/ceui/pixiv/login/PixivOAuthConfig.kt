package ceui.pixiv.login

/**
 * Immutable configuration for a Pixiv OAuth 2.0 client.
 *
 * Each Pixiv product (pixiv, pixiv Comic, pixiv Novel, …) uses a
 * **separate OAuth client** with its own credentials and endpoints.
 * Create one [PixivOAuthConfig] per product and pass it to
 * [PixivOAuthClient] — the client handles PKCE, token exchange,
 * and refresh against the matching endpoints.
 *
 * ## Predefined configurations
 *
 * [PIXIV_ANDROID] and [PIXIV_COMIC] cover the two most common
 * clients. For a custom or newly-captured client, construct the
 * data class directly:
 *
 * ```kotlin
 * val myConfig = PixivOAuthConfig(
 *     clientId     = "...",
 *     clientSecret = "...",
 *     // ...
 * )
 * ```
 *
 * ## Thread safety
 *
 * This is a data class — fully immutable, safe to share across threads
 * without synchronisation. The companion-object instances are singletons
 * and likewise safe.
 *
 * @property clientId        OAuth `client_id` issued by Pixiv. Uniquely
 *                           identifies the application (not the user).
 * @property clientSecret    OAuth `client_secret` paired with [clientId].
 *                           On mobile this is **not** truly secret — it is
 *                           compiled into the APK — but Pixiv's flow still
 *                           requires it alongside PKCE.
 * @property redirectUri     The `redirect_uri` registered with [clientId].
 *                           Must match exactly, including scheme and path,
 *                           or the token exchange will be rejected.
 * @property loginUrl        Base URL of the login page served by the
 *                           product's API gateway (e.g.
 *                           `https://app-api.pixiv.net/web/v1/login`).
 *                           [PixivOAuthClient.buildLoginUrl] appends query
 *                           parameters to this URL.
 * @property clientParam     The `client` query-parameter value appended to
 *                           the login URL. Tells the server which platform
 *                           variant to serve (e.g. `pixiv-android`,
 *                           `comic_ios`). This controls the callback
 *                           scheme the server redirects to after login.
 * @property tokenEndpointPath
 *                           Path relative to [oauthBaseUrl] for the token
 *                           endpoint. Pixiv's main app uses `auth/token`;
 *                           Comic uses `v2/auth/token`.
 * @property callbackScheme  The custom URI scheme the server redirects to
 *                           after login (e.g. `"pixiv"`, `"pixiv-manga"`).
 *                           The calling app must register an intent-filter
 *                           for this scheme so the OS routes the callback
 *                           back to the app. [PixivOAuthClient.isOAuthCallback]
 *                           uses this to identify callback URIs.
 * @property oauthBaseUrl    Base URL of the Pixiv OAuth server. All known
 *                           clients share `https://oauth.secure.pixiv.net/`.
 *                           Exposed for forward-compatibility — if Pixiv
 *                           ever moves the OAuth host, callers can override.
 */
data class PixivOAuthConfig(
    val clientId: String,
    val clientSecret: String,
    val redirectUri: String,
    val loginUrl: String,
    val clientParam: String,
    val tokenEndpointPath: String,
    val callbackScheme: String,
    val oauthBaseUrl: String = DEFAULT_OAUTH_BASE_URL,
) {

    init {
        require(clientId.isNotBlank()) { "clientId must not be blank" }
        require(clientSecret.isNotBlank()) { "clientSecret must not be blank" }
        require(redirectUri.isNotBlank()) { "redirectUri must not be blank" }
        require(loginUrl.startsWith("https://")) {
            "loginUrl must use HTTPS: $loginUrl"
        }
        require(clientParam.isNotBlank()) { "clientParam must not be blank" }
        require(tokenEndpointPath.isNotBlank()) { "tokenEndpointPath must not be blank" }
        require(callbackScheme.isNotBlank()) { "callbackScheme must not be blank" }
        require(!callbackScheme.contains("://")) {
            "callbackScheme should be the scheme only (e.g. \"pixiv\"), not a URI"
        }
        require(oauthBaseUrl.endsWith("/")) {
            "oauthBaseUrl must end with '/': $oauthBaseUrl"
        }
    }

    companion object {

        private const val DEFAULT_OAUTH_BASE_URL = "https://oauth.secure.pixiv.net/"

        /**
         * Standard Pixiv Android app.
         *
         * - Login page on `app-api.pixiv.net`.
         * - Token endpoint at `/auth/token`.
         * - Callback redirects to `pixiv://account/login?code=…`.
         */
        val PIXIV_ANDROID = PixivOAuthConfig(
            clientId = "MOBrBDS8blbauoSck0ZfDbtuzpyT",
            clientSecret = "lsACyCD94FhDUtGTXi3QzcFE2uU1hqtDaKeqrdwj",
            redirectUri = "https://app-api.pixiv.net/web/v1/users/auth/pixiv/callback",
            loginUrl = "https://app-api.pixiv.net/web/v1/login",
            clientParam = "pixiv-android",
            tokenEndpointPath = "auth/token",
            callbackScheme = "pixiv",
        )

        /**
         * Pixiv Comic (pixivコミック) iOS app.
         *
         * - Login page on `comic-api.pixiv.net`.
         * - Token endpoint at `/v2/auth/token`.
         * - Callback redirects to `pixiv-manga://account/login?code=…`.
         *
         * Uses the iOS client identity because the Android-specific
         * `client_id` (`VF09cERVVMlUVlQSRUSmeZwRyHJ6`) has no known
         * matching `client_secret` at the time of writing. The iOS
         * credentials work from any platform — the server does not
         * enforce platform checks.
         */
        val PIXIV_COMIC = PixivOAuthConfig(
            clientId = "d9GW1FKXS7iAsrZRh5qp4P7wDjeG",
            clientSecret = "RaMhKgt3LEIVwnhmDkJP1pUrwI2A1vzgHyEJPiCd",
            redirectUri = "https://comic-api.pixiv.net/web/v1/users/auth/pixiv/callback",
            loginUrl = "https://comic-api.pixiv.net/web/v1/login",
            clientParam = "comic_ios",
            tokenEndpointPath = "v2/auth/token",
            callbackScheme = "pixiv-manga",
        )
    }
}
