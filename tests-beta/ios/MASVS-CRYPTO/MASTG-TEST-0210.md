---
platform: ios
title: 不備のある対称暗号アルゴリズム (Broken Symmetric Encryption Algorithms)
id: MASTG-TEST-0210
type:
  - static
  - code
  - manual
weakness: MASWE-0020
profiles:
  - L1
  - L2
---

# MASTG-TEST-0210 不備のある対称暗号アルゴリズム (Broken Symmetric Encryption Algorithms)

### 概要

iOS アプリで不備のある暗号アルゴリズムの使用についてテストするには、暗号化および復号操作を実行するために使用される暗号フレームワークやライブラリの API に注目する必要があります。

* **CommonCrypto**: [`CCCrypt`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/CCCrypt.3cc.html) 関数は **対称アルゴリズム** に使用され、二番目のパラメータ `alg` でアルゴリズムを指定します。これは以下の [`CCAlgorithm`](https://github.com/Apple-FOSS-Mirror/CommonCrypto/blob/v60026/CommonCrypto/CommonCryptor.h#L149-L158) 定数のいずれかになります。
  * `kCCAlgorithmAES128`
  * `kCCAlgorithmDES`
  * `kCCAlgorithm3DES`
  * `kCCAlgorithmCAST`
  * `kCCAlgorithmRC4`
  * `kCCAlgorithmRC2`
  * `kCCAlgorithmBlowfish`
* **CryptoKit**: このライブラリは弱い暗号アルゴリズムをサポートしていません。AES-GCM や ChaChaPoly などの安全な **対称アルゴリズム** のみをサポートしています。
* **サードパーティライブラリ**: アプリケーションは OpenSSL, BoringSSL, Libsodium などのサードパーティライブラリ、あるいはカスタム暗号実装を通じて暗号機能を含む可能性があります。これらは DES, 3DES, RC2, RC4, Blowfish などの弱い暗号アルゴリズムをサポートしたり露出する可能性があります。

注: **Security** フレームワークは非対称アルゴリズムのみをサポートしているため、このテストではスコープ外です ([対称鍵についての注釈](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/generating_new_cryptographic_keys#2863931) 参照)。

### 手順

1. [アプリパッケージの探索 (Exploring the App Package)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0058.md) を使用して、アプリパッケージから関連するバイナリを抽出します。
2. [iOS での静的解析 (Static Analysis on iOS)](../../../techniques/ios/MASTG-TECH-0066.md) を使用して、アプリバイナリ内の関連する API を探します。

### 結果

出力には関連する暗号関数を使用する関数の逆アセンブルされたコードを含む可能性があります。

### 評価

ソースコード内に不備のある暗号アルゴリズムの使用を見つけることができた場合、そのテストケースは不合格です。たとえば、以下のものです。

* DES
* 3DES
* RC2
* RC4
* Blowfish

**さらなるバリデーションが必要となります:**

[逆アセンブルされた Objective-C と Swift のコードをレビューする (Reviewing Disassembled Objective-C and Swift Code)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0076.md) を使用して報告された各コード箇所を検査し、そのアルゴリズムが機密データを保護するためのセキュリティ関連のコンテキストで使用されているかどうかを判断します。

これは Apple が提供する API (CommonCrypto など)、サードパーティライブラリ (OpenSSL, Libsodium など)、安全でないアルゴリズム ([C コードの DES](https://github.com/tarequeh/DES/blob/master/des.c) など) を複製したり安全でない構成 (ECB モード、短い鍵サイズなど) を使用する暗号ルーチンのカスタム実装に適用します。

**最新を保つ**: これは不備のあるアルゴリズムの非網羅的なリストです。国立標準技術研究所 (NIST)、ドイツ連邦情報セキュリティ庁 (BSI)、またはお住まいの地域のその他の関連機関などの組織からの最新の標準や勧告を必ず確認してください。

アルゴリズムによっては、全体としては不備があるとはみなされないかもしれませんが、避けるべき **リスクのある構成** があるかもしれません。たとえば、暗号論的に安全な擬似乱数生成器 (CSPRNG) によって生成されていないシードや IV、あるいは量子安全であるとみなされていないものを使用することです。たとえば、AES 128 ビット鍵サイズは量子コンピューティング攻撃を対して不十分です。これは長期間保存されるデータを使用するアプリを構築する際に重要です。[NIST IR 8547 "Transition to Post-Quantum Cryptography Standards", 2024](https://csrc.nist.gov/pubs/ir/8547/ipd) の NIST 勧告に従うようにしてください。
