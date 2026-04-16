package ceui.pixiv.login

import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * PKCE (Proof Key for Code Exchange, [RFC 7636](https://tools.ietf.org/html/rfc7636))
 * utility for Pixiv's OAuth 2.0 authorization code flow.
 *
 * PKCE prevents authorization-code interception attacks on public clients
 * (mobile apps) that cannot securely store a client secret. The verifier
 * is generated locally and never leaves the device until the token exchange;
 * the challenge (a one-way hash of the verifier) is sent in the authorization
 * request so the server can verify the exchange request is from the same
 * client that initiated the flow.
 *
 * ## Usage
 *
 * ```kotlin
 * val pkce = PkceUtil.generate()
 * val loginUrl = client.buildLoginUrl(pkce.challenge)
 * // ... open loginUrl in Chrome Custom Tab ...
 * // ... receive callback with code ...
 * val result = client.exchangeCode(code, pkce.verifier)
 * ```
 *
 * The caller is responsible for persisting [PkcePair.verifier] across the
 * browser round-trip (e.g. in MMKV / SharedPreferences). This utility is
 * stateless — it generates fresh pairs on every call and does not cache.
 */
object PkceUtil {

    private const val VERIFIER_BYTE_LENGTH = 32

    /**
     * Generate a fresh PKCE pair.
     *
     * - **Verifier**: 32 cryptographically random bytes, encoded as
     *   URL-safe Base64 without padding (43 characters). Meets the
     *   RFC 7636 §4.1 requirement of 43–128 characters with the
     *   unreserved character set `[A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"`.
     *
     * - **Challenge**: SHA-256 digest of the ASCII-encoded verifier,
     *   encoded as URL-safe Base64 without padding. This is the `S256`
     *   method defined in RFC 7636 §4.2.
     */
    fun generate(): PkcePair {
        val verifier = generateVerifier()
        val challenge = computeChallenge(verifier)
        return PkcePair(verifier = verifier, challenge = challenge)
    }

    private fun generateVerifier(): String {
        val bytes = ByteArray(VERIFIER_BYTE_LENGTH)
        SecureRandom().nextBytes(bytes)
        return Base64.encodeToString(bytes, BASE64_FLAGS)
    }

    private fun computeChallenge(verifier: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(verifier.toByteArray(Charsets.US_ASCII))
        return Base64.encodeToString(hash, BASE64_FLAGS)
    }

    private const val BASE64_FLAGS = Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
}
