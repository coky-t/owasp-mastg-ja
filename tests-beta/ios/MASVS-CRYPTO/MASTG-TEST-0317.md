---
title: 不備のある対称暗号モード (Broken Symmetric Encryption Modes)
platform: ios
id: MASTG-TEST-0317
type:
  - static
  - code
  - manual
weakness: MASWE-0020
best-practices:
  - MASTG-BEST-0005
profiles:
  - L1
  - L2
---

# MASTG-TEST-0317 不備のある対称暗号モード (Broken Symmetric Encryption Modes)

### 概要

このテストは [ECB (Electronic Codebook)](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_\(ECB\)) などの不備のある対称暗号モードに焦点を当てています。

> 詳細については、[不備のある暗号モードの使用](../../../Document/0x04g-Testing-Cryptography.md#broken-block-cipher-modes) を参照してください。

iOS 開発では、最近の `CryptoKit` は ECB モードをサポートしておらず、AES-GCM や ChaCha20-Poly1305 などの安全な暗号モードのみをサポートしているため、この問題に脆弱ではありません。但し、アプリケーションが古い `CommonCrypto` ライブラリや ECB モードをサポートする可能性のあるその他のサードパーティライブラリを使用している可能性があります。この場合では、ECB モードが使用されていないことを検証することが重要です。

[`CommonCrypto`](https://web.archive.org/web/20240606000307/https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h) では、`CCCrypt` 関数の `options` パラメータに `kCCOptionECBMode` (値 `0x0002` または `2`) を設定することで ECB モードを有効にできます。options パラメータに `kCCOptionECBMode` が設定されている場合、暗号化には脆弱であるとみなされている ECB モードを使用します。デフォルトの動作 (`kCCOptionECBMode` が設定されていない場合) では CBC モードを使用します。これは適切な初期化ベクトル (IV) とともに使用するとより安全です。

### 手順

1. [アプリパッケージの探索 (Exploring the App Package)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0058.md) を使用して、アプリパッケージから関連するバイナリを抽出します。
2. [iOS での静的解析 (Static Analysis on iOS)](../../../techniques/ios/MASTG-TECH-0066.md) を使用して、アプリバイナリ内の関連する API を探します。

### 結果

出力には対称暗号化とそのモードの使用を含む可能性があります。

### 評価

ECB モードなどの不備のあるモードが有効になっている対称暗号化の使用を見つけた場合、そのテストケースは不合格です。これは `CCCrypt` の `options` パラメータに `kCCOptionECBMode` (`0x0002` または `2`) を含む場合に発生します。

**さらなるバリデーションが必要となります:**

[逆アセンブルされた Objective-C と Swift のコードをレビューする (Reviewing Disassembled Objective-C and Swift Code)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0076.md) を使用して報告された各コード箇所を検査し、これが機密データに暗号化または復号化操作をするために使用されているかどうかを判断します。
