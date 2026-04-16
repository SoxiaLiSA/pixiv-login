package ceui.pixiv.login

/**
 * Strategy for persisting the PKCE verifier between [PixivOAuthClient.startLogin]
 * and [PixivOAuthClient.handleCallback].
 *
 * The default implementation ([InMemoryVerifierStore]) keeps the verifier in a
 * `@Volatile` field — fast, zero-dependency, but **lost on process death**.
 * On Android, the system may kill the app while the user is on the Chrome Custom
 * Tab login page; when the app restarts and receives the callback intent, the
 * verifier is gone and login fails silently.
 *
 * To survive process death, implement this interface with a persistent store
 * (MMKV, SharedPreferences, EncryptedSharedPreferences, …) and pass it to
 * [PixivOAuthClient]:
 *
 * ```kotlin
 * class MmkvVerifierStore(private val mmkv: MMKV) : VerifierStore {
 *     override fun save(verifier: String) { mmkv.encode("pkce_verifier", verifier) }
 *     override fun load(): String? = mmkv.decodeString("pkce_verifier")
 *     override fun clear() { mmkv.removeValueForKey("pkce_verifier") }
 * }
 *
 * val client = PixivOAuthClient(
 *     config = PixivOAuthConfig.PIXIV_ANDROID,
 *     verifierStore = MmkvVerifierStore(mmkv),
 * )
 * ```
 *
 * ## Thread safety
 *
 * Implementations must be safe to call from any thread. The default
 * [InMemoryVerifierStore] uses `@Volatile`; persistent implementations
 * should rely on thread-safe storage (MMKV and SharedPreferences are
 * both thread-safe by default).
 */
interface VerifierStore {
    /** Persist [verifier] so it can be [load]ed after a process restart. */
    fun save(verifier: String)

    /** Return the previously [save]d verifier, or `null` if none exists. */
    fun load(): String?

    /** Delete the stored verifier (called after a successful token exchange). */
    fun clear()
}

/**
 * Default in-memory implementation. Fast but does not survive process death.
 */
internal class InMemoryVerifierStore : VerifierStore {
    @Volatile
    private var verifier: String? = null

    override fun save(verifier: String) {
        this.verifier = verifier
    }

    override fun load(): String? = verifier

    override fun clear() {
        verifier = null
    }
}
