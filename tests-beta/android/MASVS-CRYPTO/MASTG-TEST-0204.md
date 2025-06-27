---
platform: android
title: 安全でないランダム API の使用 (Insecure Random API Usage)
id: MASTG-TEST-0204
type: [static]
best-practices: [MASTG-BEST-0001]
prerequisites:
- identify-sensitive-data
- identify-security-relevant-contexts
weakness: MASWE-0027
profiles: [L1, L2]
---

## 概要

Android アプリは、安全でない [擬似乱数生成器 (PRNG)](../../../Document/0x05e-Testing-Cryptography.md#random-number-generation) を使用することがあります。たとえば、[`java.util.Random`](https://developer.android.com/reference/java/util/Random) は線形合同法生成器であり、任意のシード値に対して予測可能なシーケンスを生成します。その結果、`java.util.Random` と `Math.random()` ([後者](https://franklinta.com/2014/08/31/predicting-the-next-math-random-in-java/) は静的 `java.util.Random` インスタンスの `nextDouble()` を呼び出すだけです) は、同じシードが使用されるたびに、すべての Java 実装において再現可能なシーケンスを生成します。この予測可能性により、暗号化や他のセキュリティが重要なコンテキストには適さなくなります。

一般的に、PRNG は暗号論的に安全であると明記されていない場合、ランダム性が予測不可能でなければならない場所では使用すべきではありません。詳細については [Android ドキュメント](https://developer.android.com/privacy-and-security/risks/weak-prng) および ["乱数生成" ガイド](../../../Document/0x05e-Testing-Cryptography.md#random-number-generation) を参照してください。

## 手順

1. アプリに対して静的解析 ([Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md)) ツールを実行して、安全でないランダム API を探すか、[メソッドトレース (Method Tracing)](../../../techniques/android/MASTG-TECH-0033.md) を使用してそのような API の使用を検出します。
2. 特定された API の使用ごとに、セキュリティ関連コンテキストで使用されているかどうかをチェックします。アプリを逆コンパイル ([Java コードの逆コンパイル (Decompiling Java Code)](../../../techniques/android/MASTG-TECH-0017.md)) し、コードを検査 ([逆コンパイルされた Java コードのレビュー (Reviewing Decompiled Java Code)](../../../techniques/android/MASTG-TECH-0023.md)) して確認できます。

## 結果

出力には安全でないランダム API が使用されている場所のリストを含む可能性があります。

## 評価

パスワードや認証トークンの生成など、セキュリティ関連コンテキストにそのような API を使用して生成された乱数を見つけることができた場合、そのテストケースは不合格です。
