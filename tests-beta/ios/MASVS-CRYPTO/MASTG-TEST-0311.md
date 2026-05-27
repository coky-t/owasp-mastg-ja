---
platform: ios
title: 安全でないランダム API の使用 (Insecure Random API Usage)
id: MASTG-TEST-0311
type: [static, code, manual]
weakness: MASWE-0027
profiles: [L1, L2]
best-practices: [MASTG-BEST-0025]
knowledge: [MASTG-KNOW-0070]
---

## 概要

iOS アプリは、暗号論的に安全な擬似乱数生成器 (PRNG) ではなく、安全でない擬似乱数生成器を使用することがあります。このテストケースは、標準 C ライブラリ関数 `rand`, `random`, `*rand48` ファミリなどの安全でない API の使用を検出することに焦点を当てています。

## 手順

1. [アプリパッケージの探索 (Exploring the App Package)](../../../techniques/ios/MASTG-TECH-0058.md) を使用して、アプリパッケージから関連するバイナリを抽出します。
2. [iOS での静的解析 (Static Analysis on iOS)](../../../techniques/ios/MASTG-TECH-0066.md) を使用して、アプリバイナリ内の関連する API を探します。

## 結果

出力には安全でないランダム API が使用されている場所 (呼び出される関数名やコードの場所など) のリストを含む可能性があります。

## 評価

安全でない API を使用して生成された乱数がセキュリティ関連のコンテキストで使用される場合、そのテストケースは不合格です。

**さらなるバリデーションが必要となります:**

使用がセキュリティ関連かどうかを判断することは状況によって異なるため、[逆アセンブルされた Objective-C と Swift のコードをレビューする (Reviewing Disassembled Objective-C and Swift Code)](../../../techniques/ios/MASTG-TECH-0076.md) を使用して報告された各コード箇所を検査します。

- 生成された乱数値が、暗号鍵、初期化ベクトル (IV)、ノンス、認証トークン、セッション識別子、パスワード、PIN など、セキュリティ関連の目的に使用されているかどうかを判断します。

セキュリティに関連しない、安全でないランダム API のその他の使用 (ランダムな遅延の生成、セキュリティに関連しない識別子、ゲームメカニクスなど) は、テストケースを不合格にはしません。
