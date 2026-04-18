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
 *         // rawBody is available for custom deserialization
 *         val fullProfile = gson.fromJson(result.rawBody, MyRichResponse::class.java)
 *     }
 *     is PixivOAuthResult.Failure -> {
 *         Log.e(TAG, "OAuth failed: ${result.message}", result.cause)
 *     }
 * }
 * ```
 *
 * Or use the fluent helpers for a more concise style:
 *
 * ```kotlin
 * client.handleCallback(uri)
 *     .onSuccess { save(it.response.accessToken, it.rawBody) }
 *     .onFailure { Log.e(TAG, it.message, it.cause) }
 * ```
 *
 * Failure subtypes allow structured error handling without string matching:
 *
 * ```kotlin
 * result.onFailure { failure ->
 *     when (failure) {
 *         is Failure.MissingVerifier -> showLoginExpiredDialog()
 *         is Failure.MissingCode     -> showCallbackErrorDialog()
 *         is Failure.ServerRejected  -> log("HTTP ${failure.httpCode}: ${failure.message}")
 *         is Failure.NetworkError    -> showRetryDialog()
 *     }
 * }
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
     * The request failed. Match on the sealed subtypes to distinguish
     * failure reasons without string matching:
     *
     * - [MissingCode] — the callback URI had no `code` parameter.
     * - [MissingVerifier] — the PKCE verifier was lost (process death).
     * - [ServerRejected] — the server returned a non-2xx response, or
     *   the 2xx body could not be parsed.
     * - [NetworkError] — transport-level failure (DNS, TLS, timeout).
     */
    sealed class Failure : PixivOAuthResult() {

        /** Human-readable description suitable for debug logging. */
        abstract val message: String

        /** The underlying exception, if any. */
        abstract val cause: Throwable?

        /**
         * No `code` query parameter in the callback URI.
         *
         * This typically means the intent-filter matched an unrelated URI,
         * or the user cancelled login and the server redirected without a code.
         */
        data class MissingCode(
            override val message: String,
            override val cause: Throwable? = null,
        ) : Failure()

        /**
         * The PKCE verifier was not found in the [VerifierStore].
         *
         * Most commonly caused by process death between [PixivOAuthClient.startLogin]
         * and [PixivOAuthClient.handleCallback] when using [InMemoryVerifierStore].
         * Use a persistent [VerifierStore] to survive this, or prompt the user
         * to log in again.
         */
        data class MissingVerifier(
            override val message: String,
            override val cause: Throwable? = null,
        ) : Failure()

        /**
         * The server returned a non-2xx response, an empty body, or a body
         * that could not be parsed into [PixivOAuthResponse].
         *
         * @property httpCode HTTP status code (e.g. 400, 401, 403).
         */
        data class ServerRejected(
            val httpCode: Int,
            override val message: String,
            override val cause: Throwable? = null,
        ) : Failure()

        /**
         * Network-level failure before a response was received:
         * DNS resolution, TLS handshake, connection timeout, or
         * connection reset.
         */
        data class NetworkError(
            override val message: String,
            override val cause: Throwable? = null,
        ) : Failure()
    }

    /** `true` when this is a [Success]. */
    val isSuccess: Boolean get() = this is Success

    /** `true` when this is a [Failure]. */
    val isFailure: Boolean get() = this is Failure

    /**
     * Run [block] if this is a [Success], returning the same result
     * for chaining. The block receives the full [Success] object,
     * giving access to both [Success.response] and [Success.rawBody].
     */
    inline fun onSuccess(block: (Success) -> Unit): PixivOAuthResult {
        if (this is Success) block(this)
        return this
    }

    /**
     * Run [block] if this is a [Failure], returning the same result
     * for chaining. The block receives the [Failure] sealed type —
     * use `when` to match on specific subtypes.
     */
    inline fun onFailure(block: (Failure) -> Unit): PixivOAuthResult {
        if (this is Failure) block(this)
        return this
    }
}
