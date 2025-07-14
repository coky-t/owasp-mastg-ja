---
platform: ios
title: 不備のある対称暗号アルゴリズム (Broken Symmetric Encryption Algorithms)
id: MASTG-TEST-0210
type: [static, dynamic]
weakness: MASWE-0020
profiles: [L1, L2]
---

## 概要

iOS アプリで不備のある暗号アルゴリズムの使用についてテストするには、暗号化および復号操作を実行するために使用される暗号フレームワークやライブラリのメソッドに注目する必要があります。

- **CommonCrypto**: [`CCCrypt`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/CCCrypt.3cc.html) 関数は **対称アルゴリズム** に使用され、二番目のパラメータ `alg` でアルゴリズムを指定します。これには以下があります。
    - `kCCAlgorithmAES128`
    - `kCCAlgorithmDES`
    - `kCCAlgorithm3DES`
    - `kCCAlgorithmCAST`
    - `kCCAlgorithmRC4`
    - `kCCAlgorithmRC2`

- **CryptoKit**: このライブラリは不備のある暗号アルゴリズムをサポートしていません。以下の **対称アルゴリズム** をサポートしています。
    - `AES.GCM`
    - `ChaChaPoly`

注: **Security** フレームワークは非対称アルゴリズムのみをサポートしているため、このテストではスコープ外です ([対称鍵についての注釈](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/generating_new_cryptographic_keys#2863931) 参照)。

## 手順

1. [radare2 for iOS](../../../tools/ios/MASTG-TOOL-0073.md) などの静的解析ツールをアプリバイナリに対して実行するか、[Frida for iOS](../../../tools/ios/MASTG-TOOL-0039.md) などの動的解析ツールを使用して、暗号化および復号操作を実行する暗号関数の使用を探します。

## 結果

出力には関連する暗号関数を使用する関数の逆アセンブルされたコードを含む可能性があります。

## 評価

ソースコード内に不備のある暗号アルゴリズムの使用を見つけることができた場合、そのテストケースは不合格です。たとえば、以下のものです。

- DES
- 3DES
- RC2
- RC4

**最新を保つ**: これは不備のあるアルゴリズムの非網羅的なリストです。国立標準技術研究所 (NIST)、ドイツ連邦情報セキュリティ庁 (BSI)、またはお住まいの地域のその他の関連機関などの組織からの最新の標準や勧告を必ず確認してください。

アルゴリズムによっては、全体としては不備があるとはみなされないかもしれませんが、避けるべき **リスクのある構成** があるかもしれません。たとえば、暗号論的に安全な擬似乱数生成器 (CSPRNG) によって生成されていないシードや IV、あるいは量子安全であるとみなされていないものを使用することです。たとえば、AES 128 ビット鍵サイズは量子コンピューティング攻撃を対して不十分です。これは長期間保存されるデータを使用するアプリを構築する際に重要です。[NIST IR 8547 "Transition to Post-Quantum Cryptography Standards", 2024](https://csrc.nist.gov/pubs/ir/8547/ipd) の NIST 勧告に従うようにしてください。

**コンテキストに関する考察**:

誤検知を減らすには、関連するコードを安全でないと報告する前に、そのアルゴリズムが使用されているコンテキストを理解していることを確認してください。機密データを保護するために、セキュリティ関連コンテキストで使用されていることを確認してください。
