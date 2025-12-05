---
masvs_category: MASVS-STORAGE
platform: android
title: BouncyCastle キーストア (BouncyCastle KeyStore)
deprecated_since: 28
status: deprecated
deprecation_note: "BKS (BouncyCastle Keystore) はシステムの [KeyStore](https://developer.android.com/reference/java/security/KeyStore) プロバイダからは削除されていませんが、Android での暗号操作に対する BouncyCastle のサポートは [Android 9 (API レベル 28) で非推奨](https://developer.android.com/about/versions/pie/android-9.0-changes-all#conscrypt_implementations_of_parameters_and_algorithms) となり、最終的に [Android 12 (API レベル 31) で削除](https://developer.android.com/about/versions/12/behavior-changes-all#bouncy-castle) されました。"
covered_by: [MASTG-KNOW-0043]
---

古いバージョンの Android は [KeyStore](https://developer.android.com/reference/java/security/KeyStore) を含んでいませんが、JCA (Java Cryptography Architecture) の KeyStore インタフェースを含んで _います_。このインタフェースを実装した KeyStore を使用して、KeyStore で保存された鍵の機密性と完全性を確保します。BouncyCastle KeyStore (BKS) が推奨されます。すべての実装はファイルがファイルシステムに保存されているという事実に基づいています。すべてのファイルはパスワード保護されています。

作成するには、`KeyStore.getInstance("BKS", "BC")` メソッドを使用します。"BKS" は KeyStore 名 (BouncyCastle Keystore) であり、"BC" はプロバイダ (BouncyCastle) です。また SpongyCastle をラッパーとして使用し、次のように KeyStore を初期化することもできます: `KeyStore.getInstance("BKS", "SC")`

すべての KeyStore が KeyStore ファイルに保存されている鍵を適切に保護するわけではないことに注意してください。
