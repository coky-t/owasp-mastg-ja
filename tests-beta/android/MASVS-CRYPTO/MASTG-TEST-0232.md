---
title: 脆弱な暗号モード (Weak Encryption Modes)
platform: android
id: MASTG-TEST-0232
type: [static, dynamic]
weakness: MASWE-0020
best-practices: [MASTG-BEST-0005]
---

## 概要

Android アプリで [脆弱な暗号モードの使用](../../../Document/0x04g-Testing-Cryptography.md#weak-block-cipher-mode) をテストするには、暗号モードを構成および適用するために使用される暗号フレームワークやライブラリのメソッドに注目する必要があります。

Android 開発では、Java Cryptography Architecture (JCA) の `Cipher` クラスが暗号操作の暗号モードを指定できる主要な API です。[`Cipher.getInstance`](https://developer.android.com/reference/javax/crypto/Cipher#getInstance(java.lang.String)) は、暗号アルゴリズム、操作モード、パディングスキームを含む、変形文字列を定義します。一般的な書式は `"Algorithm/Mode/Padding"` です。たとえば、以下のとおりです。

```kotlin
Cipher.getInstance("AES/ECB/PKCS5Padding")
```

このテストでは、[ECB (Electronic Codebook)](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)) などの対称暗号モードに焦点を当てます。これは決定論的に動作し、平文をブロックに分割して個別に暗号化するため、暗号文のパターンが明らかになります。このため、[既知平文攻撃](https://en.wikipedia.org/wiki/Known-plaintext_attack) や [選択平文攻撃](https://en.wikipedia.org/wiki/Chosen-plaintext_attack) などの攻撃に対して脆弱になります。

たとえば、以下のような変形はすべて [脆弱とみなされます](https://support.google.com/faqs/answer/10046138?hl=en)。

- "AES" (uses AES/ECB mode by [default](https://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#Cipher))
- "AES/ECB/NoPadding"
- "AES/ECB/PKCS5Padding"
- "AES/ECB/ISO10126Padding"

ECB やその他のモードについては [NIST SP 800-38A - Recommendation for Block Cipher Modes of Operation: Methods and Techniques](https://csrc.nist.gov/pubs/sp/800/38/a/final) をご覧ください。また、最新情報については [Decision to Revise NIST SP 800-38A, Recommendation for Block Cipher Modes of Operation: Methods and Techniques](https://csrc.nist.gov/news/2023/decision-to-revise-nist-sp-800-38a) および [NIST IR 8459 Report on the Block Cipher Modes of Operation in the NIST SP 800-38 Series](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8459.pdf) もチェックしてください。

**スコープ外**: RSA などの非対称暗号モードは ECB などのブロックモードを使用しないため、このテストのスコープ外です。

`"RSA/ECB/OAEPPadding"` や `"RSA/ECB/PKCS1Padding"` などの変形文字列で、このコンテキストに `ECB` を含むことは誤解を招きます。対称暗号とは異なり、**RSA は ECB のようなブロックモードでは動作しません**。`ECB` の指定は [いくつかの暗号 API におけるプレースホルダ](https://github.com/openjdk/jdk/blob/680ac2cebecf93e5924a441a5de6918cd7adf118/src/java.base/share/classes/com/sun/crypto/provider/RSACipher.java#L126) であり、RSA が ECB モードを使用することを意味するものではありません。これらのニュアンスを理解することで、誤検出を防ぐことに役立ちます。

## 手順

1. アプリバイナリに対して [semgrep](../../../tools/generic/MASTG-TOOL-0110.md) などのツールで [Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md) を実行するか、[Frida for Android](../../../tools/android/MASTG-TOOL-0001.md) などのツールで [メソッドトレース (Method Tracing)](../../../techniques/android/MASTG-TECH-0033.md) (動的解析) を使用して、暗号モードを安全でないモードに指定する暗号関数を探します。

## 結果

出力には暗号操作で安全でない暗号モードや非推奨の暗号モードが使用されている場所のリストを含む可能性があります。

## 評価

アプリ内で安全でない暗号モードが特定された場合、そのテストケースは不合格です。
