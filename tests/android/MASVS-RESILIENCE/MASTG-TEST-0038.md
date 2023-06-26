---
masvs_v1_id:
- MSTG-CODE-1
masvs_v2_id:
- MASVS-RESILIENCE-2
platform: android
title: アプリが正しく署名されていることの確認 (Making Sure that the App is Properly Signed)
masvs_v1_levels:
- R
---

## 概要

## 静的解析

リリースビルドは Android 7.0 (API level 24) 以上に対して v1 および v2 の両方のスキームで署名されていること、Android 9 (API level 28) 以上に対して三つのすべてのスキームで署名されていること、および APK のコード署名証明書がその開発者に属していることを確認します。

APK 署名は `apksigner` ツールで検証できます。`[SDK-Path]/build-tools/[version]` にあります。

```bash
$ apksigner verify --verbose Desktop/example.apk
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Number of signers: 1
```

署名証明書の内容は `jarsigner` で調べることができます。デバッグ証明書では Common Name (CN) 属性が "Android Debug" に設定されることに注意します。

デバッグ証明書で署名された APK の出力は以下のとおりです。

```bash

$ jarsigner -verify -verbose -certs example.apk

sm     11116 Fri Nov 11 12:07:48 ICT 2016 AndroidManifest.xml

      X.509, CN=Android Debug, O=Android, C=US
      [certificate is valid from 3/24/16 9:18 AM to 8/10/43 9:18 AM]
      [CertPath not validated: Path doesn\'t chain with any of the trust anchors]
(...)

```

"CertPath not validated" エラーは無視します。このエラーは Java SDK 7 以上で発生します。`jarsigner` の代わりに、`apksigner` を使用して証明書チェーンを検証できます。

署名構成は Android Studio または `build.gradle` の `signingConfig` ブロックで管理できます。v1 スキームと v2 スキームの両方をアクティブにするには、以下の値をセットする必要があります。

```default
v1SigningEnabled true
v2SigningEnabled true
```

[アプリをリリース用に構成する](https://developer.android.com/tools/publishing/preparing.html#publishing-configure "Best Practices for configuring an Android App for Release") ためのいくつかのベストプラクティスが公式の Android 開発者ドキュメントに記載されています。

最後になりましたが、アプリケーションは内部テスト証明書でデプロイされることがないことを確認します。

## 動的解析

APK 署名を検証するには静的解析を使用する必要があります。
