package ceui.pixiv.login

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.util.Base64

@RunWith(RobolectricTestRunner::class)
class PkceUtilTest {

    @Test
    fun `verifier is 43 characters (32 bytes in URL-safe Base64 no padding)`() {
        val pair = PkceUtil.generate()
        assertEquals(43, pair.verifier.length)
    }

    @Test
    fun `verifier contains only URL-safe Base64 characters`() {
        val pair = PkceUtil.generate()
        assertTrue(pair.verifier.matches(Regex("[A-Za-z0-9_-]+")))
    }

    @Test
    fun `challenge is SHA-256 of verifier in URL-safe Base64`() {
        val pair = PkceUtil.generate()
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val expectedHash = digest.digest(pair.verifier.toByteArray(Charsets.US_ASCII))
        val expectedChallenge = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(expectedHash)
        assertEquals(expectedChallenge, pair.challenge)
    }

    @Test
    fun `challenge is 43 characters`() {
        val pair = PkceUtil.generate()
        assertEquals(43, pair.challenge.length)
    }

    @Test
    fun `challenge contains only URL-safe Base64 characters`() {
        val pair = PkceUtil.generate()
        assertTrue(pair.challenge.matches(Regex("[A-Za-z0-9_-]+")))
    }

    @Test
    fun `each call produces a different pair`() {
        val a = PkceUtil.generate()
        val b = PkceUtil.generate()
        assertNotEquals(a.verifier, b.verifier)
        assertNotEquals(a.challenge, b.challenge)
    }
}
