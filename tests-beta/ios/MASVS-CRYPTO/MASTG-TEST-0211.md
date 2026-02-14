---
platform: ios
title: 不備のあるハッシュアルゴリズム (Broken Hashing Algorithms)
id: MASTG-TEST-0211
type: [static, dynamic]
weakness: MASWE-0021
profiles: [L1, L2]
---

## 概要

iOS アプリで不備のあるハッシュアルゴリズムの使用についてテストするには、ハッシュ操作を実行するために使用される暗号フレームワークやライブラリのメソッドに注目する必要があります。

- **CommonCrypto**: [CommonDigest.h](https://web.archive.org/web/20240606000312/https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonDigest.h) では以下の **ハッシュアルゴリズム** を定義しています。
    - `CC_MD2`
    - `CC_MD4`
    - `CC_MD5`
    - `CC_SHA1`
    - `CC_SHA224`
    - `CC_SHA256`
    - `CC_SHA384`
    - `CC_SHA512`

- **CryptoKit**: 三つの暗号的に安全な **ハッシュアルゴリズム** と [`Insecure`](https://developer.apple.com/documentation/cryptokit/insecure) と呼ばれる専用クラスで安全でない二つのものをサポートしています。
    - `SHA256`
    - `SHA384`
    - `SHA512`
    - `Insecure.MD5`
    - `Insecure.SHA1`

注: **Security** フレームワークは非対称アルゴリズムのみをサポートしているため、このテストではスコープ外です。

## 手順

1. [radare2 for iOS](../../../tools/ios/MASTG-TOOL-0073.md) などの静的解析ツールをアプリバイナリに対して実行するか、[Frida (iOS)](../../../tools/ios/MASTG-TOOL-0039.md) などの動的解析ツールを使用して、ハッシュ操作を実行する暗号関数の使用を探します。

## 結果

出力には関連する暗号関数を使用する関数の逆アセンブルされたコードを含む可能性があります。

## 評価

ソースコード内に不備のあるハッシュアルゴリズムの使用を見つけることができた場合、そのテストケースは不合格です。たとえば、以下のものです。

- MD5
- SHA-1

**最新を保つ**: これは不備のあるアルゴリズムの非網羅的なリストです。国立標準技術研究所 (NIST)、ドイツ連邦情報セキュリティ庁 (BSI)、またはお住まいの地域のその他の関連機関などの組織からの最新の標準や勧告を必ず確認してください。これは長期間保存されるデータを使用するアプリを構築する際に重要です。[NIST IR 8547 "Transition to Post-Quantum Cryptography Standards", 2024](https://csrc.nist.gov/pubs/ir/8547/ipd) の NIST 勧告に従うようにしてください。

**コンテキストに関する考察**:

誤検知を減らすには、関連するコードを安全でないと報告する前に、そのアルゴリズムが使用されているコンテキストを理解していることを確認してください。機密データを保護するために、セキュリティ関連コンテキストで使用されていることを確認してください。

たとえば、パスワードのハッシュ化に不備のあるアルゴリズム MD5 を使用することは、暗号化の目的にはもはや安全とはみなされていないため、NIST では禁止されています。ただし、セキュリティが懸念とならないチェックサムやその他の暗号化以外のタスクに MD5 を使用することは、一般的に許容されます。
