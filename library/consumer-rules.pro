# ── kotlinx.serialization ────────────────────────────────────────────
# Keep @Serializable classes and their generated serializers so that
# R8 does not strip or rename fields that must match JSON keys.
-keepclassmembers class ceui.pixiv.login.internal.RawTokenResponse { *; }
-keepclassmembers class ceui.pixiv.login.internal.RawUser { *; }

# Keep the synthetic $$serializer companion that kotlinx.serialization
# generates — R8 can otherwise inline or remove it.
-keepclassmembers class ceui.pixiv.login.internal.RawTokenResponse$Companion { *; }
-keepclassmembers class ceui.pixiv.login.internal.RawUser$Companion { *; }

# ── Retrofit ─────────────────────────────────────────────────────────
# Retrofit creates dynamic proxies of this interface; R8 must not remove
# its methods or their parameter annotations (@Field, @Url, etc.).
-keep,allowobfuscation interface ceui.pixiv.login.internal.OAuthApi
