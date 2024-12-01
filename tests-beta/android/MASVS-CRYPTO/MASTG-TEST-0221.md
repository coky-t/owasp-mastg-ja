---
title: 脆弱な暗号アルゴリズム (Weak Encryption Algorithms)
platform: android
id: MASTG-TEST-0221
type: [static, dynamic]
weakness: MASWE-0020
---

## 概要

Android アプリで [脆弱な暗号アルゴリズムの使用](../../../Document/0x04g-Testing-Cryptography.md#identifying-insecure-andor-deprecated-cryptographic-algorithms) をテストするには、暗号化と復号化操作を実行するために使用される暗号フレームワークやライブラリのメソッドに焦点を当てる必要があります。

- [`Cipher.getInstance`](https://developer.android.com/reference/javax/crypto/Cipher#getInstance(java.lang.String)): 暗号化または復号化のために Cipher オブジェクトを初期化します。`algorithm` パラメータには [サポートされているアルゴリズム](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher) のいずれかを指定できます。
- [`SecretKeyFactory.getInstance`](https://developer.android.com/reference/javax/crypto/SecretKeyFactory#getInstance(java.lang.String)): 鍵を鍵仕様に変更したり、その逆を行う SecretKeyFactory オブジェクトを返します。`algorithm` パラメータには [サポートされているアルゴリズム](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SecretKeyFactory) のいずれかを指定できます。
- [`KeyGenerator.getInstance`](https://developer.android.com/reference/javax/crypto/KeyGenerator#getInstance(java.lang.String)): 対称アルゴリズムの秘密鍵を生成する `KeyGenerator` オブジェクトを返します。`algorithm` パラメータには [サポートされているアルゴリズム](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyGenerator) のいずれかを指定できます。

## 手順

1. アプリバイナリに対して [semgrep](../../../tools/generic/MASTG-TOOL-0110.md) などのツールで [Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md) を実行するか、[Frida for Android](../../../tools/android/MASTG-TOOL-0001.md) などのツールで [メソッドトレース (Method Tracing)](../../../techniques/android/MASTG-TECH-0033.md) (動的解析) を使用して、暗号化と復号化操作を実行する暗号関数の使用を探します。

## 結果

出力には安全でない対称暗号アルゴリズムが使用されている場所のリストを含む可能性があります。

## 評価

[安全でないか非推奨の](../../../Document/0x04g-Testing-Cryptography.md#Identifying-Insecure-and/or-Deprecated-Cryptographic-Algorithms) 暗号アルゴリズムが使用されていることを見つけた場合、そのテストケースは不合格です。

たとえば、[DES (Data Encryption Standard) と 3DES (Triple DES)](https://developer.android.com/privacy-and-security/risks/broken-cryptographic-algorithm) は、ブルートフォース攻撃や中間一致攻撃などの脆弱性があるため、[NIST SP 800-131A Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final) では非推奨になっています。それらは、現代のアプリで安全であると広く認識されている [AES-256](https://developer.android.com/privacy-and-security/cryptography#choose-algorithm) などのより強力な代替手段に置き換えてください。
