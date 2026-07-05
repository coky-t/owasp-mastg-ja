---
platform: android
title: >-
  外部ストレージにアクセスするための API とパーミッションへの参照 (References to APIs and Permissions for
  Accessing External Storage)
id: MASTG-TEST-0202
apis:
  - Environment#getExternalStoragePublicDirectory
  - Environment#getExternalStorageDirectory
  - Environment#getExternalFilesDir
  - Environment#getExternalCacheDir
  - MediaStore
  - WRITE_EXTERNAL_STORAGE
  - MANAGE_EXTERNAL_STORAGE
type:
  - static
weakness: MASWE-0007
profiles:
  - L1
  - L2
knowledge:
  - MASTG-KNOW-0042
---

# MASTG-TEST-0202 外部ストレージにアクセスするための API とパーミッションへの参照 (References to APIs and Permissions for Accessing External Storage)

### 概要

このテストでは静的解析を使用して、外部ストレージ API や `MediaStore` API など、他のアプリと共有される場所にアプリが書き込むことを許可する API の使用 ([機密データについてのローカルストレージのテスト (Testing Local Storage for Sensitive Data)](https://github.com/coky-t/owasp-mastg-ja/blob/master/tests/android/MASVS-STORAGE/MASTG-TEST-0001.md)) や、関連する Android マニフェストのストレージ関連パーミッションを探します。詳細については [外部ストレージ (External Storage)](https://github.com/coky-t/owasp-mastg-ja/blob/master/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0042.md) を参照してください。

共有ストレージへの書き込みに使用される API には `getExternalStoragePublicDirectory`, `getExternalStorageDirectory`, `getExternalFilesDir`, `MediaStore` などがあります。パーミッションには `WRITE_EXTERNAL_STORAGE` および `MANAGE_EXTERNAL_STORAGE` があります。これらの API とパーミッションの詳細については [外部ストレージ (External Storage)](https://github.com/coky-t/owasp-mastg-ja/blob/master/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0042.md) を参照してください。

> \[!NOTE] この静的テストは、アプリが共有ストレージにデータを書き込むすべてのコードの場所を特定するのに最適です。しかし、実際に書き込まれるデータや、場合によっては、データが書き込まれるデバイスストレージ内の実際のパスも提供しません。そのため、このテストを動的なアプローチを採る他のテストと組み合わせることをお勧めします。これは共有ストレージに書き込まれるデータのより完全なビューを提供することでしょう。

### 手順

1. [Android アプリのリバースエンジニアリング (Reverse Engineering Android Apps)](../../../techniques/android/MASTG-TECH-0013.md) を使用して、アプリをリバースエンジニアします。
2. [Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md) を使用して、関連する API を探します。
3. [AndroidManifest から情報の取得 (Obtaining Information from the AndroidManifest)](../../../techniques/android/MASTG-TECH-0117.md) を使用して、AndroidManifest.xml を取得します。
4. [アプリパーミッションの取得 (Obtaining App Permissions)](../../../techniques/android/MASTG-TECH-0126.md) を使用して、関連するパーミッションを取得します。

### 結果

出力には共有ストレージへの書き込みに使用される API とストレージ関連パーミッションのリストと、それらのコードの場所を含む可能性があります。

### 評価

以下のすべてが適用する場合、テストケースは不合格です。

* アプリに Android マニフェストで宣言された適切なパーミッションがあります (例: `WRITE_EXTERNAL_STORAGE`, `MANAGE_EXTERNAL_STORAGE` など)。
* the app uses APIs that write to shared storage (e.g. `getExternalStoragePublicDirectory`, `getExternalStorageDirectory`, `getExternalFilesDir`, `getExternalCacheDir`, `MediaStore`, etc.)
* 共有ストレージに書き込まれるデータは機密性が高く、暗号化されていません。

**さらなるバリデーションが必要となります:**

[逆コンパイルされた Java コードのレビュー (Reviewing Decompiled Java Code)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/android/MASTG-TECH-0023.md) を使用して、報告された各コード箇所を検査し、そのデータが機密であるかどうかを判断します。

* 共有ストレージに書き込まれたデータが機密情報 (個人データ、クレデンシャル、トークンなど) を含むかどうかを判断します。
* データが暗号化なしで保存されているかどうかを判断します。
