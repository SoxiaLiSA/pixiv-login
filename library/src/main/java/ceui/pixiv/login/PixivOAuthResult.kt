package ceui.pixiv.login

/**
 * Outcome of a Pixiv OAuth operation ([PixivOAuthClient.handleCallback],
 * [PixivOAuthClient.exchangeCode], or [PixivOAuthClient.refreshToken]).
 *
 * Callers should exhaustively match both branches:
 *
 * ```kotlin
 * when (val result = client.handleCallback(uri)) {
 *     is PixivOAuthResult.Success -> {
 *         save(result.response.accessToken, result.response.refreshToken)
 *     }
 *     is PixivOAuthResult.Failure -> {
 *         Log.e(TAG, "OAuth failed: HTTP ${result.httpCode} — ${result.message}", result.cause)
 *     }
 * }
 * ```
 *
 * Or use the fluent helpers for a more concise style:
 *
 * ```kotlin
 * client.handleCallback(uri)
 *     .onSuccess { save(it.accessToken, it.refreshToken) }
 *     .onFailure { Log.e(TAG, it.message, it.cause) }
 * ```
 *
 * ## Why not `kotlin.Result`?
 *
 * `kotlin.Result` erases the failure type to `Throwable` and cannot carry
 * structured metadata (HTTP status code, server error body) without wrapping
 * in a custom exception. A sealed class gives callers exhaustive matching
 * and direct access to all failure context without `catch`/`is`-casting.
 */
sealed class PixivOAuthResult {

    /**
     * The server accepted the request and returned tokens.
     *
     * @property response parsed token response with [PixivOAuthResponse.accessToken],
     *                    [PixivOAuthResponse.refreshToken], and optional user profile.
     * @property rawBody  the raw JSON response body from the server. Callers
     *                    that need fields beyond what [PixivOAuthResponse]
     *                    exposes (e.g. a full user profile with R18 settings,
     *                    `device_token`, etc.) can re-deserialize this into
     *                    their own richer model type using Gson / Moshi /
     *                    kotlinx.serialization.
     */
    data class Success(
        val response: PixivOAuthResponse,
        val rawBody: String,
    ) : PixivOAuthResult()

    /**
     * The request failed — either the server rejected it or a network /
     * serialisation error occurred.
     *
     * @property httpCode HTTP status code if the server responded (e.g. 400,
     *                    401, 403). `null` when the failure happened before
     *                    a response was received (DNS, TLS, timeout) or when
     *                    the error is purely client-side (missing PKCE verifier).
     * @property message  Human-readable description. For server errors this
     *                    is the raw error body; for transport errors it is
     *                    the exception message. Suitable for debug logging,
     *                    **not** for user-facing UI.
     * @property cause    The underlying exception, if any. `null` for
     *                    server-side rejections that returned a valid HTTP
     *                    response (the server said "no", but the transport
     *                    worked fine), and for client-side validation errors
     *                    (missing code, missing verifier).
     */
    data class Failure(
        val httpCode: Int?,
        val message: String,
        val cause: Throwable? = null,
    ) : PixivOAuthResult()

    /** `true` when this is a [Success]. */
    val isSuccess: Boolean get() = this is Success

    /** `true` when this is a [Failure]. */
    val isFailure: Boolean get() = this is Failure

    /**
     * Run [block] if this is a [Success], returning the same result
     * for chaining.
     */
    inline fun onSuccess(block: (PixivOAuthResponse) -> Unit): PixivOAuthResult {
        if (this is Success) block(response)
        return this
    }

    /**
     * Run [block] if this is a [Failure], returning the same result
     * for chaining.
     */
    inline fun onFailure(block: (Failure) -> Unit): PixivOAuthResult {
        if (this is Failure) block(this)
        return this
    }
}
