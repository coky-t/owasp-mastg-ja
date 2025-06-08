---
title: コード内にハードコードされた暗号鍵の使用 (Use of Hardcoded Cryptographic Keys in Code)
platform: ios
id: MASTG-TEST-0213
type: [static]
weakness: MASWE-0014
profiles: [L1, L2]
---

## 概要

このテストケースでは、iOS アプリケーションでハードコードされた暗号鍵の存在を調べます。通常、ハードコードされた鍵は暗号関数の呼び出しで見つかるか、コード内の定数や変数に格納されています。iOS では、暗号鍵は以下のフレームワークでよく使用されます。

- **Security Framework**: [`SecKeyCreateWithData`](https://developer.apple.com/documentation/security/seckeycreatewithdata(_:_:_:)) 関数は開発者が Raw データから暗号鍵を作成できます。
- **CommonCrypto**: [`CCCrypt`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/CCCrypt.3cc.html) は Raw 鍵データで `key` パラメータを初期化できます。
- **CryptoKit**: `CryptoKit` は暗号操作のための高レベルの抽象化を提供しますが、開発者は依然としてさまざまな形式で暗号鍵をハードコードし、[`P256.Signing.PrivateKey.init(rawRepresentation:)`](https://developer.apple.com/documentation/cryptokit/p256/signing/privatekey/init(rawrepresentation:)) などのメソッドに渡すかもしれません。

## 手順

1. [radare2 for iOS](../../../tools/ios/MASTG-TOOL-0073.md) などの静的解析ツールをアプリバイナリに対して実行して、上記の暗号 API を探します。

## 結果

出力にはアプリが Raw の鍵データを受け入れる暗号関数を使用するインスタンスを含む可能性があります。可能であれば、出力にはバイナリからの Raw の鍵データを指す可能性もあります。

## 評価

バイナリ内にハードコードされた鍵での暗号関数の呼び出しを見つけることができた場合、そのテストは不合格です。

暗号関数への引数 (バイト配列や文字列リテラル) として直接渡されたり、コード内の変数や定数に格納されている鍵が見つかるかもしれません。ハードコードされた鍵の典型的な表現には以下があります。

- **Raw バイト配列**: 暗号鍵は `UInt8` の配列や `Data` オブジェクトとしてコード内に直接埋め込まれることがあります。たとえば、256 ビット AES 鍵は `[UInt8]` 配列として表現されるかもしれません。
- **Base64 エンコードされた文字列**: 開発者はコード内で暗号鍵を Base64 文字列としてエンコードするかもしれません。発見された場合、攻撃者によって簡単にデコードされる可能性があります。
- **16 進エンコードされた文字列**: 鍵は 16 進文字列として保存されることがあり、暗号操作のために実行時に `Data` オブジェクトに変換されます。

特定された鍵が本当にセキュリティ関連の目的で使用される暗号鍵であることを確認します。鍵の使用コンテキストを検証して誤検知を回避します (たとえば、構成設定やセキュリティに関連しない定数が暗号鍵として誤って特定されるかもしれません)。
