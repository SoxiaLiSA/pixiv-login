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

    @Test(expected = IllegalArgumentException::class)
    fun `blank clientSecret is rejected`() {
        PixivOAuthConfig(
            clientId = "id",
            clientSecret = "  ",
            redirectUri = "https://example.com/callback",
            loginUrl = "https://example.com/login",
            clientParam = "test",
            tokenEndpointPath = "auth/token",
            callbackScheme = "test",
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `non-HTTPS loginUrl is rejected`() {
        PixivOAuthConfig(
            clientId = "id",
            clientSecret = "secret",
            redirectUri = "https://example.com/callback",
            loginUrl = "http://example.com/login",
            clientParam = "test",
            tokenEndpointPath = "auth/token",
            callbackScheme = "test",
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `blank clientParam is rejected`() {
        PixivOAuthConfig(
            clientId = "id",
            clientSecret = "secret",
            redirectUri = "https://example.com/callback",
            loginUrl = "https://example.com/login",
            clientParam = "",
            tokenEndpointPath = "auth/token",
            callbackScheme = "test",
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `blank tokenEndpointPath is rejected`() {
        PixivOAuthConfig(
            clientId = "id",
            clientSecret = "secret",
            redirectUri = "https://example.com/callback",
            loginUrl = "https://example.com/login",
            clientParam = "test",
            tokenEndpointPath = "  ",
            callbackScheme = "test",
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `blank callbackScheme is rejected`() {
        PixivOAuthConfig(
            clientId = "id",
            clientSecret = "secret",
            redirectUri = "https://example.com/callback",
            loginUrl = "https://example.com/login",
            clientParam = "test",
            tokenEndpointPath = "auth/token",
            callbackScheme = "",
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `oauthBaseUrl without HTTP or HTTPS is rejected`() {
        PixivOAuthConfig(
            clientId = "id",
            clientSecret = "secret",
            redirectUri = "https://example.com/callback",
            loginUrl = "https://example.com/login",
            clientParam = "test",
            tokenEndpointPath = "auth/token",
            callbackScheme = "test",
            oauthBaseUrl = "ftp://example.com/",
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `oauthBaseUrl without trailing slash is rejected`() {
        PixivOAuthConfig(
            clientId = "id",
            clientSecret = "secret",
            redirectUri = "https://example.com/callback",
            loginUrl = "https://example.com/login",
            clientParam = "test",
            tokenEndpointPath = "auth/token",
            callbackScheme = "test",
            oauthBaseUrl = "https://example.com",
        )
    }

    @Test
    fun `custom HTTP oauthBaseUrl is accepted for local testing`() {
        val config = PixivOAuthConfig(
            clientId = "id",
            clientSecret = "secret",
            redirectUri = "https://example.com/callback",
            loginUrl = "https://example.com/login",
            clientParam = "test",
            tokenEndpointPath = "auth/token",
            callbackScheme = "test",
            oauthBaseUrl = "http://localhost:8080/",
        )
        assertEquals("http://localhost:8080/", config.oauthBaseUrl)
    }

    @Test
    fun `data class equality works for identical configs`() {
        val a = PixivOAuthConfig(
            clientId = "id",
            clientSecret = "secret",
            redirectUri = "https://example.com/callback",
            loginUrl = "https://example.com/login",
            clientParam = "test",
            tokenEndpointPath = "auth/token",
            callbackScheme = "test",
        )
        val b = a.copy()
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }

    @Test
    fun `PIXIV_ANDROID has expected field values`() {
        val config = PixivOAuthConfig.PIXIV_ANDROID
        assertEquals("MOBrBDS8blbauoSck0ZfDbtuzpyT", config.clientId)
        assertEquals("pixiv-android", config.clientParam)
        assertEquals("auth/token", config.tokenEndpointPath)
        assertEquals("https://app-api.pixiv.net/web/v1/login", config.loginUrl)
    }

    @Test
    fun `PIXIV_COMIC has expected field values`() {
        val config = PixivOAuthConfig.PIXIV_COMIC
        assertEquals("d9GW1FKXS7iAsrZRh5qp4P7wDjeG", config.clientId)
        assertEquals("comic_ios", config.clientParam)
        assertEquals("v2/auth/token", config.tokenEndpointPath)
        assertEquals("https://comic-api.pixiv.net/web/v1/login", config.loginUrl)
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
