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
 */
data class PixivOAuthResponse(
    val accessToken: String,
    val refreshToken: String,
    val expiresIn: Int,
    val tokenType: String,
    val scope: String,
    val user: PixivOAuthUser?,
)

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
