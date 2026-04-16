package ceui.pixiv.login.internal

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import retrofit2.Call
import retrofit2.http.Field
import retrofit2.http.FormUrlEncoded
import retrofit2.http.POST
import retrofit2.http.Url

/**
 * Raw Retrofit interface for Pixiv's OAuth token endpoint.
 *
 * This is an **internal** implementation detail — callers interact with
 * [ceui.pixiv.login.PixivOAuthClient], not this interface. The `@Url`
 * parameter allows each [ceui.pixiv.login.PixivOAuthConfig] to target
 * a different token endpoint path without creating multiple Retrofit
 * service instances.
 *
 * Returns [Call] (not `suspend fun`) because callers include both
 * coroutine code (login flow) and synchronous OkHttp interceptor code
 * (token refresh). `Call.execute()` is the common denominator.
 */
internal interface OAuthApi {

    @FormUrlEncoded
    @POST
    fun token(
        @Url url: String,
        @Field("client_id") clientId: String,
        @Field("client_secret") clientSecret: String,
        @Field("grant_type") grantType: String,
        @Field("code") code: String? = null,
        @Field("code_verifier") codeVerifier: String? = null,
        @Field("refresh_token") refreshToken: String? = null,
        @Field("redirect_uri") redirectUri: String? = null,
        @Field("include_policy") includePolicy: Boolean = true,
        @Field("get_secure_url") getSecureUrl: Boolean = true,
    ): Call<RawTokenResponse>
}

// ── Wire-format models ──────────────────────────────────────────────
//
// Snake_case field names match the JSON the server returns. These are
// mapped to the public PixivOAuthResponse / PixivOAuthUser types by
// PixivOAuthClient before leaving the library boundary.

@Serializable
internal data class RawTokenResponse(
    val access_token: String,
    val refresh_token: String,
    val expires_in: Int = 3600,
    val token_type: String = "bearer",
    val scope: String = "",
    val user: RawUser? = null,
)

@Serializable
internal data class RawUser(
    val id: Long = 0,
    val name: String = "",
    val account: String = "",
)
