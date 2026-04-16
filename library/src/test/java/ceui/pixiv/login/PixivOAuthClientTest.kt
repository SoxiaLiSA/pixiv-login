package ceui.pixiv.login

import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class PixivOAuthClientTest {

    private lateinit var server: MockWebServer
    private lateinit var client: PixivOAuthClient

    private fun testConfig(baseUrl: String) = PixivOAuthConfig(
        clientId = "test-client-id",
        clientSecret = "test-client-secret",
        redirectUri = "https://app-api.pixiv.net/web/v1/users/auth/pixiv/callback",
        loginUrl = "https://app-api.pixiv.net/web/v1/login",
        clientParam = "pixiv-android",
        tokenEndpointPath = "auth/token",
        callbackScheme = "pixiv",
        oauthBaseUrl = baseUrl,
    )

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
        val baseUrl = server.url("/").toString()
        client = PixivOAuthClient(testConfig(baseUrl))
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    // ── startLogin / buildLoginUrl ─────────────────────────────────

    @Test
    fun `startLogin returns URL with PKCE challenge`() {
        val url = client.startLogin()
        assertTrue(url.contains("code_challenge="))
        assertTrue(url.contains("code_challenge_method=S256"))
        assertTrue(url.contains("client=pixiv-android"))
    }

    @Test
    fun `buildLoginUrl includes all required params`() {
        val url = client.buildLoginUrl("test-challenge")
        assertTrue(url.contains("code_challenge=test-challenge"))
        assertTrue(url.contains("code_challenge_method=S256"))
        assertTrue(url.contains("client=pixiv-android"))
    }

    // ── exchangeCode ───────────────────────────────────────────────

    @Test
    fun `exchangeCode returns Success on valid response`() {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(VALID_TOKEN_RESPONSE),
        )

        val result = client.exchangeCode("test-code", "test-verifier")

        assertTrue(result.isSuccess)
        val response = (result as PixivOAuthResult.Success).response
        assertEquals("access_token_value", response.accessToken)
        assertEquals("refresh_token_value", response.refreshToken)
        assertEquals(3600, response.expiresIn)
        assertEquals("bearer", response.tokenType)
    }

    @Test
    fun `exchangeCode sends correct form fields`() {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(VALID_TOKEN_RESPONSE),
        )

        client.exchangeCode("my-code", "my-verifier")

        val request = server.takeRequest()
        val body = request.body.readUtf8()
        assertTrue(body.contains("grant_type=authorization_code"))
        assertTrue(body.contains("code=my-code"))
        assertTrue(body.contains("code_verifier=my-verifier"))
        assertTrue(body.contains("client_id=test-client-id"))
        assertTrue(body.contains("client_secret=test-client-secret"))
    }

    @Test
    fun `exchangeCode returns Failure on HTTP 400`() {
        server.enqueue(
            MockResponse()
                .setResponseCode(400)
                .setBody("""{"error":"invalid_grant"}"""),
        )

        val result = client.exchangeCode("bad-code", "verifier")

        assertTrue(result.isFailure)
        val failure = result as PixivOAuthResult.Failure
        assertEquals(400, failure.httpCode)
        assertNull(failure.cause)
    }

    @Test
    fun `exchangeCode returns Success with user info when present`() {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(TOKEN_RESPONSE_WITH_USER),
        )

        val result = client.exchangeCode("code", "verifier")
        val response = (result as PixivOAuthResult.Success).response

        assertNotNull(response.user)
        assertEquals(12345L, response.user!!.id)
        assertEquals("testuser", response.user!!.name)
        assertEquals("test_account", response.user!!.account)
    }

    // ── refreshToken ───────────────────────────────────────────────

    @Test
    fun `refreshToken sends refresh_token grant type`() {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(VALID_TOKEN_RESPONSE),
        )

        client.refreshToken("my-refresh-token")

        val request = server.takeRequest()
        val body = request.body.readUtf8()
        assertTrue(body.contains("grant_type=refresh_token"))
        assertTrue(body.contains("refresh_token=my-refresh-token"))
    }

    // ── PixivOAuthResult helpers ───────────────────────────────────

    @Test
    fun `onSuccess callback is invoked for Success`() {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(VALID_TOKEN_RESPONSE),
        )

        var token: String? = null
        client.exchangeCode("code", "verifier")
            .onSuccess { token = it.accessToken }

        assertEquals("access_token_value", token)
    }

    @Test
    fun `onFailure callback is invoked for Failure`() {
        server.enqueue(MockResponse().setResponseCode(500).setBody("error"))

        var failMsg: String? = null
        client.exchangeCode("code", "verifier")
            .onFailure { failMsg = it.message }

        assertNotNull(failMsg)
    }

    companion object {
        private val VALID_TOKEN_RESPONSE = """
            {
                "access_token": "access_token_value",
                "refresh_token": "refresh_token_value",
                "expires_in": 3600,
                "token_type": "bearer",
                "scope": ""
            }
        """.trimIndent()

        private val TOKEN_RESPONSE_WITH_USER = """
            {
                "access_token": "access_token_value",
                "refresh_token": "refresh_token_value",
                "expires_in": 3600,
                "token_type": "bearer",
                "scope": "",
                "user": {
                    "id": 12345,
                    "name": "testuser",
                    "account": "test_account"
                }
            }
        """.trimIndent()
    }
}
