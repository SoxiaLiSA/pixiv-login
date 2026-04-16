package ceui.pixiv.login

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

class PixivOAuthConfigTest {

    @Test
    fun `PIXIV_ANDROID has expected callback scheme`() {
        assertEquals("pixiv", PixivOAuthConfig.PIXIV_ANDROID.callbackScheme)
    }

    @Test
    fun `PIXIV_COMIC has expected callback scheme`() {
        assertEquals("pixiv-manga", PixivOAuthConfig.PIXIV_COMIC.callbackScheme)
    }

    @Test
    fun `predefined configs are not null`() {
        assertNotNull(PixivOAuthConfig.PIXIV_ANDROID)
        assertNotNull(PixivOAuthConfig.PIXIV_COMIC)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `blank clientId is rejected`() {
        PixivOAuthConfig(
            clientId = "",
            clientSecret = "secret",
            redirectUri = "https://example.com/callback",
            loginUrl = "https://example.com/login",
            clientParam = "test",
            tokenEndpointPath = "auth/token",
            callbackScheme = "test",
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `non-HTTPS redirectUri is rejected`() {
        PixivOAuthConfig(
            clientId = "id",
            clientSecret = "secret",
            redirectUri = "http://example.com/callback",
            loginUrl = "https://example.com/login",
            clientParam = "test",
            tokenEndpointPath = "auth/token",
            callbackScheme = "test",
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `loginUrl with query params is rejected`() {
        PixivOAuthConfig(
            clientId = "id",
            clientSecret = "secret",
            redirectUri = "https://example.com/callback",
            loginUrl = "https://example.com/login?foo=bar",
            clientParam = "test",
            tokenEndpointPath = "auth/token",
            callbackScheme = "test",
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `tokenEndpointPath with leading slash is rejected`() {
        PixivOAuthConfig(
            clientId = "id",
            clientSecret = "secret",
            redirectUri = "https://example.com/callback",
            loginUrl = "https://example.com/login",
            clientParam = "test",
            tokenEndpointPath = "/auth/token",
            callbackScheme = "test",
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `callbackScheme containing colon-slash-slash is rejected`() {
        PixivOAuthConfig(
            clientId = "id",
            clientSecret = "secret",
            redirectUri = "https://example.com/callback",
            loginUrl = "https://example.com/login",
            clientParam = "test",
            tokenEndpointPath = "auth/token",
            callbackScheme = "pixiv://",
        )
    }

    @Test
    fun `valid custom config is accepted`() {
        val config = PixivOAuthConfig(
            clientId = "myId",
            clientSecret = "mySecret",
            redirectUri = "https://example.com/callback",
            loginUrl = "https://example.com/login",
            clientParam = "my-client",
            tokenEndpointPath = "v2/auth/token",
            callbackScheme = "myscheme",
        )
        assertEquals("myId", config.clientId)
        assertEquals("myscheme", config.callbackScheme)
    }
}
