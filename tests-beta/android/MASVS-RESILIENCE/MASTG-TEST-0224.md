---
title: 安全でない署名バージョンの使用 (Usage of Insecure Signature Version)
platform: android
id: MASTG-TEST-0x39-1
type: [static]
available_since: 24
weakness: MASWE-0104
---

## 概要

新しい APK 署名スキームを使用しないということは、アプリにはより堅牢で更新されたメカニズムによって提供される強化されたセキュリティが欠如していることを意味します。

このテストでは、古い v1 署名スキームが有効になっているかどうかをチェックします。v1 スキームは、APK ファイルのすべての部分をカバーしていないため、"Janus" 脆弱性 ([CVE-2017-13156](https://nvd.nist.gov/vuln/detail/CVE-2017-13156)) などの特定の攻撃に対して脆弱であり、悪意のあるアクターが **署名を無効にすることなく APK の一部を変更** できる可能性があります。したがって、v1 署名のみに依存すると、改竄のリスクが高まり、アプリのセキュリティが損なわれます。

APK 署名スキームの詳細については、["署名プロセス"](../../../Document/0x05a-Platform-Overview.md#signing-process) を参照してください。

## 手順

1. [AndroidManifest から情報の取得 (Obtaining Information from the AndroidManifest)](../../../techniques/android/MASTG-TECH-0117.md) などで AndroidManifest.xml から `minSdkVersion` 属性を取得します。
2. [APK 署名に関する情報の取得 (Obtaining Information about the APK Signature)](../../../techniques/android/MASTG-TECH-0116.md) に示されているように、使用されているすべての署名スキームをリストします。

## 結果

出力には `minSdkVersion` 属性の値と、使用されている署名スキーム (たとえば `Verified using v3 scheme (APK Signature Scheme v3): true`) を含む可能性があります。

## 評価

アプリの `minSdkVersion` 属性が 24 以上で、v1 署名スキームのみが有効になっている場合、そのテストケースは不合格です。

この問題を緩和するには、少なくとも v2 または v3 の APK 署名スキームでアプリが署名されているようにします。これらは包括的な完全性チェックを提供し、APK 全体を改竄から保護します。最適なセキュリティと互換性のためには、鍵ローテーションもサポートする v3 の使用を検討してください。

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
