---
masvs_v1_id:
- MSTG-CODE-1
masvs_v2_id:
- MASVS-RESILIENCE-2
platform: android
title: アプリが正しく署名されていることの確認 (Making Sure that the App is Properly Signed)
masvs_v1_levels:
- R
profiles: [R]
status: deprecated
covered_by: [MASTG-TEST-0224, MASTG-TEST-0225]
deprecation_note: New version available in MASTG V2
---

## 概要

リリースビルドが適切に署名されていることを確認し、完全性を保護して改竄から保護します。Android は時間とともに署名スキームを進化させており、セキュリティを強化して、新しいバージョンではより堅牢なメカニズムを提供しています。

- **Android 7.0 (API レベル 24) 以降**: 少なくとも **v2 署名スキーム** を使用してください。このスキームは APK 全体を署名し、古い v1 (JAR) 署名方式に比べてより強力な保護を提供します。
- **Android 9 (API レベル 28) 以降**: **v2 と v3 署名スキーム** の両方を使用することをお勧めします。v3 スキームは **キーローテーション** をサポートしており、侵害が発生した際に開発者は古い署名を無効にすることなくキーを交換できます。
- **Android 11 (API レベル 30) 以降**: オプションで **v4 署名スキーム** を含めると、より高速なインクリメンタルアップデートが可能になります。

**v1 署名スキーム** (JAR 署名) は安全でないと考えられているため、Android 6.0 (API レベル 23) 以前との後方互換性のために絶対に必要な場合を除き、使用を避けてください。たとえば、**Janus 脆弱性 (CVE-2017-13156)** の影響を受けて、悪意のあるアクターが v1 署名を無効にすることなく APK ファイルを変更できる可能性があります。そのため、**Android 7.0 以上を実行しているデバイスに限っては、v1 は決して信頼すべきではありません。**。

また、APK のコード署名証明書が有効であり、開発者のものであることを確認する必要があります。

詳しいガイダンスについては、公式の [Android アプリ署名ドキュメント](https://developer.android.com/studio/publish/app-signing) と、[リリース用アプリを構成する](https://developer.android.com/tools/publishing/preparing.html#publishing-configure) ためのベストプラクティスを参照してください。

## 静的解析

APK 署名は [apksigner](https://developer.android.com/tools/apksigner) ツールで検証できます。`[SDK-Path]/build-tools/[version]/apksigner` にあります。

```bash
$ apksigner verify --verbose example.apk
Verifies
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Verified using v3.1 scheme (APK Signature Scheme v3.1): false
Verified using v4 scheme (APK Signature Scheme v4): false
Verified for SourceStamp: false
Number of signers: 1
```

署名証明書の内容も apksigner で調べることができます。

```bash
$ apksigner verify --print-certs --verbose example.apk
[...]
Signer #1 certificate DN: CN=Example Developers, OU=Android, O=Example
Signer #1 certificate SHA-256 digest: 1fc4de52d0daa33a9c0e3d67217a77c895b46266ef020fad0d48216a6ad6cb70
Signer #1 certificate SHA-1 digest: 1df329fda8317da4f17f99be83aa64da62af406b
Signer #1 certificate MD5 digest: 3dbdca9c1b56f6c85415b67957d15310
Signer #1 key algorithm: RSA
Signer #1 key size (bits): 2048
Signer #1 public key SHA-256 digest: 296b4e40a31de2dcfa2ed277ccf787db0a524db6fc5eacdcda5e50447b3b1a26
Signer #1 public key SHA-1 digest: 3e02ebf64f1bd4ca85732186b3774e9ccd60cb86
Signer #1 public key MD5 digest: 24afa3496f98c66343fc9c8a0a7ff5a2
```

署名構成は Android Studio または、`build.gradle` または `build.gradle.kts` の `signingConfigs` セクションで管理できます。v3 スキームと v4 スキームの両方をアクティブにするには、以下の値をセットする必要があります。

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

APK v4 署名はオプションであり、それがなくても脆弱性を意味するものではないことに注意してください。これは、開発者が Android 11 以降の [ADB 増分 APK インストール](https://developer.android.com/about/versions/11/features#incremental) を使用して、大規模の APK を迅速にデプロイできるようにするためのものです。

## 動的解析

APK 署名を検証するには静的解析を使用する必要があります。
