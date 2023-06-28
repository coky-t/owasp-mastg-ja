---
masvs_v1_id:
- MSTG-PLATFORM-8
masvs_v2_id:
- MASVS-CODE-4
platform: ios
title: オブジェクト永続化のテスト (Testing Object Persistence)
masvs_v1_levels:
- L1
- L2
---

## 概要

## 静的解析

オブジェクト永続化にはさまざまな種類がありますが、すべて以下の共通した懸念事項があります。

- オブジェクト永続化を使用してデバイスに機密情報を保存する場合、データがデータベースレベル、あるいはより効果的には値レベルで暗号化されていることを確認します。
- 情報の完全性を保証する必要がありますか？HMAC メカニズムを使用するか、保存される情報に署名します。オブジェクトに格納されている実際の情報を処理する前に、必ず HMAC や署名を検証します。
- 上記の二つの観点で使用される鍵が KeyChain に安全に保存され、十分に保護されていることを確認します。詳細については "[iOS のデータストレージ](../../../Document/0x06d-Testing-Data-Storage.md)" の章を参照してください。
- デシリアライズされたオブジェクト内のデータは実際に使用される前に注意深く検証されていることを確認します (たとえば、ビジネスロジックやアプリケーションロジックの悪用ができないこと) 。
- 高リスクのアプリケーションでは、[Runtime Reference](https://developer.apple.com/library/archive/#documentation/Cocoa/Reference/ObjCRuntimeRef/Reference/reference.html "Objective-C Runtime Reference") を使用してオブジェクトをシリアライズやデシリアライズする永続化メカニズムを使用しないでください。攻撃者はこのメカニズムを介してビジネスロジックを実行するステップを操作できる可能性があります (詳細については "[iOS のアンチリバース防御](../../../Document/0x06j-Testing-Resiliency-Against-Reverse-Engineering.md)" の章を参照してください) 。
- Swift 2 以降では、[Mirror](https://developer.apple.com/documentation/swift/mirror "Mirror") を使用してオブジェクトのパーツを読み取ることができますが、オブジェクトに対する書き込みには使用できないことに注意してください。

## 動的解析

動的解析を実行するにはいくつかの方法があります。

- 実際の永続化には: 「iOS のデータストレージ」の章で説明されている技法を使用します。
- シリアライズ自体には: デバッグビルトを使用するか、Frida や objection を使用してシリアライズメソッドがどのように処理されるかを確認します (たとえば、アプリケーションがクラッシュするかどうか、オブジェクトをエンリッチすることでその他の情報を抽出できるかなど) 。
