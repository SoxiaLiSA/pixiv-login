package ceui.pixiv.login

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.SocketPolicy
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
import java.util.concurrent.TimeUnit

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

    // ── startProvisionalAccount / buildProvisionalAccountUrl ──────

    @Test
    fun `startProvisionalAccount returns URL with PKCE challenge`() {
        val url = client.startProvisionalAccount()
        assertTrue(url.contains("provisional-accounts/create"))
        assertTrue(url.contains("code_challenge="))
        assertTrue(url.contains("code_challenge_method=S256"))
        assertTrue(url.contains("client=pixiv-android"))
    }

    @Test
    fun `buildProvisionalAccountUrl includes all required params`() {
        val url = client.buildProvisionalAccountUrl("test-challenge")
        assertTrue(url.contains("provisional-accounts/create"))
        assertTrue(url.contains("code_challenge=test-challenge"))
        assertTrue(url.contains("code_challenge_method=S256"))
        assertTrue(url.contains("client=pixiv-android"))
    }

    @Test
    fun `startProvisionalAccount stores verifier for handleCallback`() {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(VALID_TOKEN_RESPONSE),
        )

        client.startProvisionalAccount()

        val uri = android.net.Uri.parse("pixiv://account/login?code=test-code")
        val result = client.handleCallback(uri)
        assertTrue(result.isSuccess)
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
    fun `exchangeCode exposes rawBody for custom deserialization`() {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(TOKEN_RESPONSE_WITH_USER),
        )

        val result = client.exchangeCode("code", "verifier") as PixivOAuthResult.Success
        // rawBody contains the original JSON — callers can re-parse into richer types
        assertTrue(result.rawBody.contains("\"access_token\""))
        assertTrue(result.rawBody.contains("\"user\""))
        assertTrue(result.rawBody.contains("\"testuser\""))
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
        val failure = result as PixivOAuthResult.Failure.ServerRejected
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
            .onSuccess { token = it.response.accessToken }

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

    // ── Default headers ────────────────────────────────────────────

    @Test
    fun `default headers are sent when addDefaultHeaders is true`() {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(VALID_TOKEN_RESPONSE),
        )

        client.exchangeCode("code", "verifier")

        val request = server.takeRequest()
        assertNotNull(request.getHeader("User-Agent"))
        assertTrue(request.getHeader("User-Agent")!!.startsWith("PixivAndroidApp/"))
        assertEquals("android", request.getHeader("App-OS"))
        assertNotNull(request.getHeader("App-OS-Version"))
        assertNotNull(request.getHeader("X-Client-Time"))
        assertNotNull(request.getHeader("X-Client-Hash"))
    }

    @Test
    fun `default headers are not sent when addDefaultHeaders is false`() {
        val noHeaderClient = PixivOAuthClient(
            testConfig(server.url("/").toString()),
            addDefaultHeaders = false,
        )
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(VALID_TOKEN_RESPONSE),
        )

        noHeaderClient.exchangeCode("code", "verifier")

        val request = server.takeRequest()
        assertNull(request.getHeader("App-OS"))
        assertNull(request.getHeader("X-Client-Time"))
        assertNull(request.getHeader("X-Client-Hash"))
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
        assertTrue(result is PixivOAuthResult.Failure.MissingVerifier)
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
        assertEquals(400, (result as PixivOAuthResult.Failure.ServerRejected).httpCode)
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

    // ── isOAuthCallback ──────────────────────────────────────────────

    @Test
    fun `isOAuthCallback returns true for matching scheme`() {
        val uri = android.net.Uri.parse("pixiv://account/login?code=test")
        assertTrue(client.isOAuthCallback(uri))
    }

    @Test
    fun `isOAuthCallback returns false for non-matching scheme`() {
        val uri = android.net.Uri.parse("https://example.com/callback")
        assertFalse(client.isOAuthCallback(uri))
    }

    // ── tryHandleCallback ────────────────────────────────────────────

    @Test
    fun `tryHandleCallback returns null for null intent`() {
        assertNull(client.tryHandleCallback(null))
    }

    @Test
    fun `tryHandleCallback returns null for intent without data`() {
        assertNull(client.tryHandleCallback(android.content.Intent()))
    }

    @Test
    fun `tryHandleCallback returns null for non-OAuth URI`() {
        val intent = android.content.Intent().apply {
            data = android.net.Uri.parse("https://example.com/page")
        }
        assertNull(client.tryHandleCallback(intent))
    }

    @Test
    fun `tryHandleCallback exchanges code for valid callback`() {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(VALID_TOKEN_RESPONSE),
        )
        client.startLogin()
        val intent = android.content.Intent().apply {
            data = android.net.Uri.parse("pixiv://account/login?code=test-code")
        }
        val result = client.tryHandleCallback(intent)
        assertNotNull(result)
        assertTrue(result!!.isSuccess)
    }

    // ── handleCallback edge cases ────────────────────────────────────

    @Test
    fun `handleCallback fails when code parameter is missing`() {
        client.startLogin()
        val uri = android.net.Uri.parse("pixiv://account/login")
        val result = client.handleCallback(uri)
        assertTrue(result.isFailure)
        assertTrue(result is PixivOAuthResult.Failure.MissingCode)
        assertTrue((result as PixivOAuthResult.Failure).message.contains("No 'code'"))
    }

    @Test
    fun `handleCallback preserves verifier on exchange failure`() {
        val store = object : VerifierStore {
            var saved: String? = null
            var clearCount = 0
            override fun save(verifier: String) { saved = verifier }
            override fun load(): String? = saved
            override fun clear() { clearCount++; saved = null }
        }
        val customClient = PixivOAuthClient(
            testConfig(server.url("/").toString()),
            verifierStore = store,
        )
        customClient.startLogin()

        server.enqueue(
            MockResponse().setResponseCode(400).setBody("""{"error":"invalid_grant"}"""),
        )
        val uri = android.net.Uri.parse("pixiv://account/login?code=bad-code")
        val result = customClient.handleCallback(uri)

        assertTrue(result.isFailure)
        assertEquals(0, store.clearCount)
        assertNotNull(store.saved)
    }

    // ── Network error ────────────────────────────────────────────────

    @Test
    fun `exchangeCode returns Failure on connection reset`() {
        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AT_START))

        val result = client.exchangeCode("code", "verifier")

        assertTrue(result.isFailure)
        val failure = result as PixivOAuthResult.Failure.NetworkError
        assertNotNull(failure.cause)
    }

    // ── refreshToken detailed ────────────────────────────────────────

    @Test
    fun `refreshToken returns Success with parsed tokens`() {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(VALID_TOKEN_RESPONSE),
        )

        val result = client.refreshToken("old-refresh-token")

        assertTrue(result.isSuccess)
        val response = (result as PixivOAuthResult.Success).response
        assertEquals("access_token_value", response.accessToken)
        assertEquals("refresh_token_value", response.refreshToken)
    }

    @Test
    fun `refreshToken returns Failure on HTTP 401`() {
        server.enqueue(
            MockResponse()
                .setResponseCode(401)
                .setBody("""{"error":"invalid_token"}"""),
        )

        val result = client.refreshToken("expired-token")

        assertTrue(result.isFailure)
        assertEquals(401, (result as PixivOAuthResult.Failure.ServerRejected).httpCode)
    }

    // ── PixivOAuthResult chaining ────────────────────────────────────

    @Test
    fun `onSuccess is not invoked for Failure`() {
        server.enqueue(MockResponse().setResponseCode(400).setBody("error"))

        var invoked = false
        client.exchangeCode("code", "verifier")
            .onSuccess { invoked = true }

        assertFalse(invoked)
    }

    @Test
    fun `onFailure is not invoked for Success`() {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(VALID_TOKEN_RESPONSE),
        )

        var invoked = false
        client.exchangeCode("code", "verifier")
            .onFailure { invoked = true }

        assertFalse(invoked)
    }

    @Test
    fun `onSuccess and onFailure chain on Success`() {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(VALID_TOKEN_RESPONSE),
        )

        var successToken: String? = null
        var failureInvoked = false

        client.exchangeCode("code", "verifier")
            .onSuccess { successToken = it.response.accessToken }
            .onFailure { failureInvoked = true }

        assertEquals("access_token_value", successToken)
        assertFalse(failureInvoked)
    }

    @Test
    fun `onSuccess and onFailure chain on Failure`() {
        server.enqueue(MockResponse().setResponseCode(500).setBody("error"))

        var successInvoked = false
        var failureMsg: String? = null

        client.exchangeCode("code", "verifier")
            .onSuccess { successInvoked = true }
            .onFailure { failureMsg = it.message }

        assertFalse(successInvoked)
        assertNotNull(failureMsg)
    }

    // ── Suspend edge cases ───────────────────────────────────────────

    @Test
    fun `tryHandleCallbackSuspend returns null for non-OAuth intent`() = runTest {
        val intent = android.content.Intent().apply {
            data = android.net.Uri.parse("https://example.com/page")
        }
        assertNull(client.tryHandleCallbackSuspend(intent))
    }

    @Test
    fun `handleCallbackSuspend fails when code is missing`() = runTest {
        client.startLogin()
        val uri = android.net.Uri.parse("pixiv://account/login")
        val result = client.handleCallbackSuspend(uri)
        assertTrue(result.isFailure)
        assertTrue(result is PixivOAuthResult.Failure.MissingCode)
        assertTrue((result as PixivOAuthResult.Failure).message.contains("No 'code'"))
    }

    @Test
    fun `handleCallbackSuspend fails when verifier is missing`() = runTest {
        val uri = android.net.Uri.parse("pixiv://account/login?code=test")
        val result = client.handleCallbackSuspend(uri)
        assertTrue(result.isFailure)
        assertTrue(result is PixivOAuthResult.Failure.MissingVerifier)
        assertTrue(
            (result as PixivOAuthResult.Failure).message.contains("No pending PKCE verifier"),
        )
    }

    @Test
    fun `handleCallbackSuspend clears verifier on success`() = runTest {
        val store = object : VerifierStore {
            var saved: String? = null
            var cleared = false
            override fun save(verifier: String) { saved = verifier }
            override fun load(): String? = saved
            override fun clear() { cleared = true; saved = null }
        }
        val customClient = PixivOAuthClient(
            testConfig(server.url("/").toString()),
            verifierStore = store,
        )
        customClient.startLogin()

        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(VALID_TOKEN_RESPONSE),
        )
        val uri = android.net.Uri.parse("pixiv://account/login?code=test-code")
        val result = customClient.handleCallbackSuspend(uri)

        assertTrue(result.isSuccess)
        assertTrue(store.cleared)
    }

    @Test
    fun `refreshTokenSuspend returns Failure on HTTP 401`() = runTest {
        server.enqueue(
            MockResponse()
                .setResponseCode(401)
                .setBody("""{"error":"invalid"}"""),
        )

        val result = client.refreshTokenSuspend("bad-token")

        assertTrue(result.isFailure)
        assertEquals(401, (result as PixivOAuthResult.Failure.ServerRejected).httpCode)
    }

    @Test
    fun `exchangeCodeSuspend returns Failure on connection reset`() = runTest {
        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AT_START))

        val result = client.exchangeCodeSuspend("code", "verifier")

        assertTrue(result.isFailure)
        val failure = result as PixivOAuthResult.Failure.NetworkError
        assertNotNull(failure.cause)
    }

    // ── Cancellation ─────────────────────────────────────────────────

    @Test
    fun `exchangeCodeSuspend cancels HTTP request on coroutine cancellation`() = runBlocking {
        // Use a dedicated server to avoid tearDown issues with pending delayed responses.
        val delayServer = MockWebServer()
        delayServer.start()
        val delayClient = PixivOAuthClient(testConfig(delayServer.url("/").toString()))

        delayServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(VALID_TOKEN_RESPONSE)
                .setBodyDelay(10, TimeUnit.SECONDS),
        )

        val startTime = System.currentTimeMillis()
        val job = launch(Dispatchers.IO) {
            delayClient.exchangeCodeSuspend("code", "verifier")
        }

        delay(300)
        job.cancelAndJoin()

        val elapsed = System.currentTimeMillis() - startTime
        assertTrue("Should cancel quickly, took ${elapsed}ms", elapsed < 3000)

        try { delayServer.shutdown() } catch (_: Exception) { }
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
