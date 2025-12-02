---
platform: ios
title: 安全でないランダム API の使用 (Insecure Random API Usage)
id: MASTG-TEST-0311
type: [static, dynamic]
weakness: MASWE-0027
profiles: [L1, L2]
best-practices: [MASTG-BEST-0025]
---

## 概要

iOS アプリは、暗号論的に安全な擬似乱数生成器 (PRNG) ([乱数生成 (Random Number Generator)](../../../knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0070.md)) ではなく、安全でない擬似乱数生成器を使用することがあります。このテストケースは、標準 C ライブラリ関数 `rand`, `random`, `*rand48` ファミリなどの安全でない代替手段の使用を検出することに焦点を当てています。

## 手順

1. アプリバイナリに対して [radare2 for iOS](../../../tools/ios/MASTG-TOOL-0073.md) などの静的解析スキャンを実行するか、ランタイムメソッドフック ([メソッドフック (Method Hooking)](../../../techniques/ios/MASTG-TECH-0095.md) 参照) を使用し、安全でないランダム API を探します。

## 結果

出力には安全でないランダム API が使用されている場所 (呼び出される関数名やコードの場所など) のリストを含む可能性があります。

## 評価

安全でない API を使用して生成された乱数がセキュリティ関連のコンテキストで使用される場合、そのテストケースは不合格です。

特定された API の使用ごとに、コードを逆コンパイルまたは逆アセンブルしてコンテキストを検証 ([逆アセンブルされた Objective-C と Swift のコードをレビューする (Reviewing Disassembled Objective-C and Swift Code)](../../../techniques/ios/MASTG-TECH-0076.md) を参照) して、生成された乱数が以下のようなセキュリティ関連の目的で使用されているかどうかを判断します。

- 暗号鍵、初期化ベクトル (IV)、ノンスの生成
- 認証トークンやセッション識別子の作成
- パスワードや PIN の生成
- 予測不可能性を必要とするその他のセキュリティ関連の操作

セキュリティに関連しない、安全でないランダム API のその他の使用 (ランダムな遅延の生成、セキュリティに関連しない識別子、ゲームメカニクスなど) は、テストケースを不合格にはしません。
