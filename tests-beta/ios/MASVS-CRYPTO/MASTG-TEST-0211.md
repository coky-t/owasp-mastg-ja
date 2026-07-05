---
platform: ios
title: 不備のあるハッシュアルゴリズム (Broken Hashing Algorithms)
id: MASTG-TEST-0211
type: [static, code, manual]
weakness: MASWE-0021
profiles: [L1, L2]
---

## 概要

iOS アプリで不備のあるハッシュアルゴリズムの使用についてテストするには、ハッシュ操作を実行するために使用される暗号フレームワークやライブラリの API に注目する必要があります。

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

1. [アプリパッケージの探索 (Exploring the App Package)](../../../techniques/ios/MASTG-TECH-0058.md) を使用して、アプリパッケージから関連するバイナリを抽出します。
2. [iOS での静的解析 (Static Analysis on iOS)](../../../techniques/ios/MASTG-TECH-0066.md) を使用して、アプリバイナリ内の関連する API を探します。

## 結果

出力には関連する暗号関数を使用する関数の逆アセンブルされたコードを含む可能性があります。

## 評価

ソースコード内に不備のあるハッシュアルゴリズムの使用を見つけることができた場合、そのテストケースは不合格です。たとえば、以下のものです。

- MD5
- SHA-1

**さらなるバリデーションが必要となります:**

[逆アセンブルされた Objective-C と Swift のコードをレビューする (Reviewing Disassembled Objective-C and Swift Code)](../../../techniques/ios/MASTG-TECH-0076.md) を使用して報告された各コード箇所を検査し、そのアルゴリズムが機密データを保護するためのセキュリティ関連のコンテキストで使用されているかどうかを判断します。

- ハッシュアルゴリズムが、チェックサムなどの非セキュリティタスクではなく、暗号論的セキュリティ目的で使用されているかどうかを判断します。たとえば、パスワードのハッシュ化に MD5 を使用することは NIST によって禁止されていますが、セキュリティの懸念がないチェックサムに MD5 を使用することは一般的に許容できます。

**最新を保つ**: これは不備のあるアルゴリズムの非網羅的なリストです。国立標準技術研究所 (NIST)、ドイツ連邦情報セキュリティ庁 (BSI)、またはお住まいの地域のその他の関連機関などの組織からの最新の標準や勧告を必ず確認してください。これは長期間保存されるデータを使用するアプリを構築する際に重要です。[NIST IR 8547 "Transition to Post-Quantum Cryptography Standards", 2024](https://csrc.nist.gov/pubs/ir/8547/ipd) の NIST 勧告に従うようにしてください。
