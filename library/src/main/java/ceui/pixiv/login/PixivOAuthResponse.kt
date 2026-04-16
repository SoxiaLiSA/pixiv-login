package ceui.pixiv.login

/**
 * Parsed token response from a successful Pixiv OAuth token exchange
 * or refresh.
 *
 * Field names follow Kotlin conventions rather than the wire format
 * (`access_token` → [accessToken]). The wire-format mapping is handled
 * internally by the serialisation layer; callers never see snake_case.
 *
 * @property accessToken  Short-lived bearer token for API requests.
 *                        Typically expires in [expiresIn] seconds (3600
 *                        for most Pixiv clients).
 * @property refreshToken Long-lived token used to obtain a new
 *                        [accessToken] without re-authenticating the user.
 *                        Stored securely and sent only to the token endpoint.
 * @property expiresIn    Token lifetime in seconds as reported by the
 *                        server. Note: this is the server's claim at the
 *                        time of issuance — actual validity may differ
 *                        under clock skew or early revocation.
 * @property tokenType    Always `"bearer"` for Pixiv.
 * @property scope        Space-separated list of granted scopes. Currently
 *                        empty for most Pixiv clients.
 * @property user         Authenticated user profile, if the server included
 *                        it. May be `null` on refresh responses from some
 *                        Pixiv products.
 * @property issuedAtMillis [System.currentTimeMillis] captured at the
 *                          moment the token response was received. Combined
 *                          with [expiresIn] to determine when the token
 *                          expires without relying on server clock sync.
 */
data class PixivOAuthResponse(
    val accessToken: String,
    val refreshToken: String,
    val expiresIn: Int,
    val tokenType: String,
    val scope: String,
    val user: PixivOAuthUser?,
    val issuedAtMillis: Long = System.currentTimeMillis(),
) {

    /**
     * Absolute expiration time in milliseconds since epoch.
     *
     * Equivalent to `issuedAtMillis + expiresIn * 1000L`.
     */
    val expiresAtMillis: Long get() = issuedAtMillis + expiresIn * 1000L

    /**
     * `true` when the access token has expired according to the local
     * clock. Compares [expiresAtMillis] against [System.currentTimeMillis].
     *
     * Does **not** account for clock skew or early server-side revocation.
     * For a conservative check, call [isExpired] with a margin:
     * ```kotlin
     * if (response.isExpired(marginMillis = 60_000)) { refresh() }
     * ```
     *
     * @param marginMillis extra milliseconds to subtract from the
     *                     remaining lifetime. Pass a positive value to
     *                     treat the token as expired *before* it actually
     *                     expires, giving time to refresh proactively.
     *                     Defaults to `0`.
     * @param now          current time in milliseconds since epoch.
     *                     Defaults to [System.currentTimeMillis].
     *                     Pass an explicit value in tests for
     *                     deterministic assertions.
     */
    fun isExpired(marginMillis: Long = 0, now: Long = System.currentTimeMillis()): Boolean =
        now + marginMillis >= expiresAtMillis
}

/**
 * Minimal user profile returned inline with the token response.
 *
 * This is **not** a full user profile — it contains only what the OAuth
 * server embeds in the token response. Use the Pixiv API's dedicated
 * user endpoints for profile images, follow counts, etc.
 *
 * @property id      Pixiv user ID (numeric, globally unique).
 * @property name    Display name (nickname) chosen by the user.
 * @property account Pixiv login account name (unique, URL-safe slug).
 */
data class PixivOAuthUser(
    val id: Long,
    val name: String,
    val account: String,
)
