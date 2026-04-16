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
 * ## When to use directly
 *
 * Most callers should use [PixivOAuthClient.startLogin], which generates
 * and caches the PKCE pair internally. Use this utility directly only if
 * you need to persist the [PkcePair.verifier] yourself to survive process
 * death:
 *
 * ```kotlin
 * val pkce = PkceUtil.generate()
 * mmkv.encode("verifier", pkce.verifier)          // persist
 * val url = client.buildLoginUrl(pkce.challenge)   // low-level API
 * // ... callback ...
 * val result = client.exchangeCode(code, mmkv.decodeString("verifier")!!)
 * ```
 *
 * This utility is stateless — it generates a fresh pair on every call
 * and does not cache.
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
     *
     * SHA-256 is guaranteed to be available on all Android devices
     * (it is a mandatory JCA provider), so this method never throws.
     */
    @JvmStatic
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

    /** URL-safe Base64 without line breaks or padding, per RFC 7636 Appendix A. */
    private const val BASE64_FLAGS = Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
}
