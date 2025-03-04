---
title: 脆弱な対称暗号アルゴリズム (Weak Symmetric Encryption Algorithms)
platform: android
id: MASTG-TEST-0221
type: [static, dynamic]
weakness: MASWE-0020
best-practices: [MASTG-BEST-0009]
---

## 概要

Android アプリで [脆弱な暗号アルゴリズムの使用](../../../Document/0x04g-Testing-Cryptography.md#identifying-insecure-andor-deprecated-cryptographic-algorithms) をテストするには、暗号化と復号化操作を実行するために使用される暗号フレームワークやライブラリのメソッドに焦点を当てる必要があります。

- [`Cipher.getInstance`](https://developer.android.com/reference/javax/crypto/Cipher#getInstance(java.lang.String)): 暗号化または復号化のために Cipher オブジェクトを初期化します。`algorithm` パラメータには [サポートされているアルゴリズム](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher) のいずれかを指定できます。
- [`SecretKeyFactory.getInstance`](https://developer.android.com/reference/javax/crypto/SecretKeyFactory#getInstance(java.lang.String)): 鍵を鍵仕様に変更したり、その逆を行う SecretKeyFactory オブジェクトを返します。`algorithm` パラメータには [サポートされているアルゴリズム](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SecretKeyFactory) のいずれかを指定できます。
- [`KeyGenerator.getInstance`](https://developer.android.com/reference/javax/crypto/KeyGenerator#getInstance(java.lang.String)): 対称アルゴリズムの秘密鍵を生成する `KeyGenerator` オブジェクトを返します。`algorithm` パラメータには [サポートされているアルゴリズム](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyGenerator) のいずれかを指定できます。

脆弱な対称暗号アルゴリズムには以下のようなものがあります。

- **DES (Data Encryption Standard)**: 56 ビット鍵、解読可能、[2005 年に NIST により撤回されました](https://csrc.nist.gov/pubs/fips/46-3/final)。
- **3DES (Triple DES, 正式には Triple Data Encryption Algorithm (TDEA もしくは Triple DEA))**: 脆弱な 64 ビットブロック、[Sweet32 バイナリ攻撃に脆弱](https://sweet32.info/)、[2024 年 1 月 1 日に NIST により撤回されました](https://csrc.nist.gov/pubs/sp/800/67/r2/final)。
- **RC4**: 予測可能な鍵ストリーム、プレーンテキストの復元が可能な [RC4 の脆弱性](https://www.rc4nomore.com/)、2014 年に [NIST](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-52r1.pdf) によって不承認、2015 年に [IETF](https://datatracker.ietf.org/doc/html/rfc7465) によって禁止されました。
- **Blowfish**: 64 ビットブロックサイズ、[Sweet32 攻撃に脆弱](https://en.wikipedia.org/wiki/Birthday_attack)、FIPS 承認は受けておらず、[FIPS の「非承認アルゴリズム」](https://csrc.nist.gov/csrc/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp2092.pdf) にリストされています。

Android では [破られた暗号アルゴリズム](https://developer.android.com/privacy-and-security/risks/broken-cryptographic-algorithm) に関する追加のガイダンスも提供しています。

## 手順

1. アプリバイナリに対して [semgrep](../../../tools/generic/MASTG-TOOL-0110.md) などのツールで [Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md) を実行するか、[Frida for Android](../../../tools/android/MASTG-TOOL-0001.md) などのツールで [メソッドトレース (Method Tracing)](../../../techniques/android/MASTG-TECH-0033.md) (動的解析) を使用して、暗号化と復号化操作を実行する暗号関数の使用を探します。

## 結果

出力には安全でない対称暗号アルゴリズムが使用されている場所のリストを含む可能性があります。

## 評価

[安全でないか非推奨の](../../../Document/0x04g-Testing-Cryptography.md#identifying-insecure-andor-deprecated-cryptographic-algorithms) 暗号アルゴリズムが使用されていることを見つけた場合、そのテストケースは不合格です。
