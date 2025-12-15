---
title: 最新の APK 署名スキームを使用する (Use Up-to-Date APK Signing Schemes)
alias: use-up-to-date-apk-signing-schemes
id: MASTG-BEST-0006
platform: android
knowledge: [MASTG-KNOW-0003]
---

少なくとも v2 または v3 の APK 署名スキームでアプリが署名されているようにします。これらは包括的な完全性チェックを提供し、APK 全体を改竄から保護します。最適なセキュリティと互換性のためには、鍵ローテーションもサポートする v3 の使用を検討してください。

オプションとして、Android 11 および以降ではより高速な [増分アップデート](https://developer.android.com/about/versions/11/features#incremental) を可能にする v4 署名を追加できますが、v4 だけではセキュリティ保護を提供しないため、v2 または v3 と一緒に使用する必要があります。

署名の設定は Android Studio や、`build.gradle` または `build.gradle.kts` の `signingConfigs` セクションで管理できます。v3 と v4 の両方のスキームを有効にするには、以下の値を設定しなければなりません。

```default
// build.gradle
android {
  ...
  signingConfigs {
    config {
        ...
        enableV3Signing true
        enableV4Signing true
    }
  }
}
```
