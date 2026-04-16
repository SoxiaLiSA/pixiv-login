package ceui.pixiv.login

import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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

    // ── issuedAtMillis ────────────────────────────────────────────

    @Test
    fun `response includes issuedAtMillis close to current time`() {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(VALID_TOKEN_RESPONSE),
        )

        val before = System.currentTimeMillis()
        val result = client.exchangeCode("code", "verifier") as PixivOAuthResult.Success
        val after = System.currentTimeMillis()

        assertTrue(result.response.issuedAtMillis in before..after)
    }

    @Test
    fun `expiresAtMillis equals issuedAtMillis plus expiresIn seconds`() {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(VALID_TOKEN_RESPONSE),
        )

        val response = (client.exchangeCode("code", "verifier") as PixivOAuthResult.Success).response
        assertEquals(
            response.issuedAtMillis + response.expiresIn * 1000L,
            response.expiresAtMillis,
        )
    }

    @Test
    fun `freshly issued token is not expired`() {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(VALID_TOKEN_RESPONSE),
        )

        val response = (client.exchangeCode("code", "verifier") as PixivOAuthResult.Success).response
        assertFalse(response.isExpired())
    }

    // ── VerifierStore ─────────────────────────────────────────────

    @Test
    fun `custom VerifierStore is used for startLogin and handleCallback`() {
        val store = object : VerifierStore {
            var saved: String? = null
            var cleared = false
            override fun save(verifier: String) { saved = verifier }
            override fun load(): String? = saved
            override fun clear() { cleared = true; saved = null }
        }

        val customClient = PixivOAuthClient(testConfig(server.url("/").toString()), verifierStore = store)

        // startLogin should save the verifier
        customClient.startLogin()
        assertNotNull(store.saved)

        // handleCallback with a successful exchange should clear it
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(VALID_TOKEN_RESPONSE),
        )
        val uri = android.net.Uri.parse("pixiv://account/login?code=test-code")
        val result = customClient.handleCallback(uri)
        assertTrue(result.isSuccess)
        assertTrue(store.cleared)
    }

    @Test
    fun `handleCallback fails when VerifierStore returns null`() {
        val emptyStore = object : VerifierStore {
            override fun save(verifier: String) {}
            override fun load(): String? = null
            override fun clear() {}
        }

        val customClient = PixivOAuthClient(testConfig(server.url("/").toString()), verifierStore = emptyStore)
        val uri = android.net.Uri.parse("pixiv://account/login?code=test-code")
        val result = customClient.handleCallback(uri)

        assertTrue(result.isFailure)
        assertTrue((result as PixivOAuthResult.Failure).message.contains("No pending PKCE verifier"))
    }

    // ── isExpired with explicit now ─────────────────────────────────

    @Test
    fun `isExpired returns false when now is before expiry`() {
        val issued = 1_000_000L
        val response = PixivOAuthResponse(
            accessToken = "a", refreshToken = "r", expiresIn = 3600,
            tokenType = "bearer", scope = "", user = null,
            issuedAtMillis = issued,
        )
        // 1 second before expiry
        assertFalse(response.isExpired(now = issued + 3599_000L))
    }

    @Test
    fun `isExpired returns true when now is at expiry`() {
        val issued = 1_000_000L
        val response = PixivOAuthResponse(
            accessToken = "a", refreshToken = "r", expiresIn = 3600,
            tokenType = "bearer", scope = "", user = null,
            issuedAtMillis = issued,
        )
        assertTrue(response.isExpired(now = issued + 3600_000L))
    }

    @Test
    fun `isExpired respects margin`() {
        val issued = 1_000_000L
        val response = PixivOAuthResponse(
            accessToken = "a", refreshToken = "r", expiresIn = 3600,
            tokenType = "bearer", scope = "", user = null,
            issuedAtMillis = issued,
        )
        // 60s before actual expiry, but with 60s margin → expired
        assertTrue(response.isExpired(marginMillis = 60_000, now = issued + 3540_000L))
        // 61s before actual expiry, with 60s margin → not expired
        assertFalse(response.isExpired(marginMillis = 60_000, now = issued + 3539_000L))
    }

    // ── Suspend API ──────────────────────────────────────────────────

    @Test
    fun `exchangeCodeSuspend returns Success`() = runTest {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(VALID_TOKEN_RESPONSE),
        )

        val result = client.exchangeCodeSuspend("code", "verifier")
        assertTrue(result.isSuccess)
        assertEquals("access_token_value", (result as PixivOAuthResult.Success).response.accessToken)
    }

    @Test
    fun `exchangeCodeSuspend returns Failure on error`() = runTest {
        server.enqueue(MockResponse().setResponseCode(400).setBody("""{"error":"invalid"}"""))

        val result = client.exchangeCodeSuspend("bad", "verifier")
        assertTrue(result.isFailure)
        assertEquals(400, (result as PixivOAuthResult.Failure).httpCode)
    }

    @Test
    fun `refreshTokenSuspend returns Success`() = runTest {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(VALID_TOKEN_RESPONSE),
        )

        val result = client.refreshTokenSuspend("my-refresh")
        assertTrue(result.isSuccess)
    }

    @Test
    fun `tryHandleCallbackSuspend returns null for null intent`() = runTest {
        val result = client.tryHandleCallbackSuspend(null)
        assertNull(result)
    }

    @Test
    fun `handleCallbackSuspend exchanges code successfully`() = runTest {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(VALID_TOKEN_RESPONSE),
        )

        // Need to startLogin first so verifier is stored
        client.startLogin()

        val uri = android.net.Uri.parse("pixiv://account/login?code=test-code")
        val result = client.handleCallbackSuspend(uri)
        assertTrue(result.isSuccess)
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
