---
platform: ios
title: 安全でないランダム API の実行時使用 (Runtime Use of Insecure Random APIs)
id: MASTG-TEST-0349
type: [dynamic, hooks, manual]
weakness: MASWE-0012
profiles: [L1, L2]
best-practices: [MASTG-BEST-0025]
knowledge: [MASTG-KNOW-0070]
---

## 概要

アプリが実行時に安全でない擬似乱数生成器 (PRNG) を使用する場合、生成される値は予測可能となる可能性があります。これは、これらの値がセキュリティ関連のコンテキストで使用される際に、弱いトークン、ナンス、鍵、識別子につながる可能性があります。このテストは、実行しているアプリが、関連するフローの中で、`rand`, `random`, `*rand48` ファミリーなどの安全でないランダム API を呼び出しているかどうかをチェックします。

## 手順

1. [アプリのインストール (Installing Apps)](../../../techniques/ios/MASTG-TECH-0056.md) を使用して、アプリをインストールします。
2. [メソッドフック (Method Hooking)](../../../techniques/ios/MASTG-TECH-0095.md) を使用して、関連する API をフックします。
3. アプリを徹底的に動かして、できるだけ多くのフローをトリガーし、可能な限り機密データを入力します。

## 結果

出力には、関数名やバックトレースを含め、安全でないランダム API へのランタイム呼び出しを含む可能性があります。

## 評価

安全でない API によって生成された乱数値がセキュリティ関連のコンテキストで使用されている場合、このテストケースは不合格です。

**さらなるバリデーションが必要となります:**

フックの出力からのバックトレースを使用し、[逆アセンブルされた Objective-C と Swift のコードをレビューする (Reviewing Disassembled Objective-C and Swift Code)](../../../techniques/ios/MASTG-TECH-0076.md) を使用してそのコード箇所を検査し、その使用がセキュリティ関連であるかどうかを判断します。

- 生成された乱数値が、暗号鍵、初期化ベクトル (IV)、ナンス、認証トークン、セッション識別子、パスワード、PIN の生成など、セキュリティ関連の用途に使用されているかどうかを判断します。
