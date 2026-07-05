---
platform: ios
title: 不十分な鍵サイズ (Insufficient Key Sizes)
id: MASTG-TEST-0209
type:
  - static
  - code
weakness: MASWE-0009
profiles:
  - L1
  - L2
---

# MASTG-TEST-0209 不十分な鍵サイズ (Insufficient Key Sizes)

### 概要

このテストケースでは、iOS アプリでの不十分な鍵サイズの使用を探します。そのためには、iOS で利用できる暗号フレームワークとライブラリの API、および暗号鍵の生成に使用されるメソッドに注目する必要があります。

* **CommonCrypto**: [`CCCrypt`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/CCCrypt.3cc.html) 関数は対称暗号化と復号に使用され、五番目のパラメータ `keyLength` で鍵サイズまたは鍵長を指定します。
* **Security**: [`SecKeyCreateRandomKey`](https://developer.apple.com/documentation/security/1823694-seckeycreaterandomkey) 関数は [`kSecAttrKeyType`](https://developer.apple.com/documentation/security/ksecattrkeytype) や [`kSecAttrKeySizeInBits`](https://developer.apple.com/documentation/security/ksecattrkeysizeinbits) などの特定の属性を使用してランダム鍵を生成するために使用されます。[`SecKeyGeneratePair`](https://developer.apple.com/documentation/security/1395339-seckeygeneratepair) 関数は iOS 16 で非推奨になりました。
* **CryptoKit**: [`AES.GCM`](https://developer.apple.com/documentation/cryptokit/aes/gcm) と [`ChaChaPoly`](https://developer.apple.com/documentation/cryptokit/chachapoly) クラスは対称暗号化と復号に使用されます。

通常、CryptoKit で鍵を直接生成することはありません (ライブラリが自動的に行います) ので、このテストでは CommonCrypto ライブラリと Security ライブラリに焦点を当てます。

### 手順

1. [アプリパッケージの探索 (Exploring the App Package)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0058.md) を使用して、アプリパッケージから関連するバイナリを抽出します。
2. [iOS での静的解析 (Static Analysis on iOS)](../../../techniques/ios/MASTG-TECH-0066.md) を使用して、アプリバイナリ内の関連する API を探します。

### 結果

出力には `CCCrypt` や他の暗号関数を使用する関数の逆アセンブルされたコードを含む可能性があります。

### 評価

ソースコード内に不十分な鍵サイズの使用を見つけることができた場合、そのテストケースは不合格です。たとえば、量子コンピューティング攻撃を考慮すると、1024 ビットの鍵サイズは RSA 暗号では不十分であるとみなされ、128 ビットの鍵サイズは AES 暗号では不十分であるとみなされます。
