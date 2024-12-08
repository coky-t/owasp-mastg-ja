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
---

## 概要

Android アプリは、基本的に線形合同法生成器である `java.util.Random` などの安全でない擬似乱数生成器 (PRNG) を使用することがあります。この種の PRNG は任意のシード値に対して予測可能な数値シーケンスを生成するため、シーケンスは予測可能となり、暗号に使用するには安全ではありません。特に、`java.util.Random` と `Math.random()` ([後者](https://franklinta.com/2014/08/31/predicting-the-next-math-random-in-java/) は静的 `java.util.Random` インスタンスの `nextDouble()` を呼び出すだけです) は、すべての Java 実装において同じシードで初期化された場合、同じ数値シーケンスを生成します。

## 手順

1. アプリに対して静的解析 ([Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md)) ツールを実行して、安全でないランダム API を探します。

## 結果

出力には安全でないランダム API が使用されている場所のリストを含む可能性があります。

## 評価

セキュリティ関連コンテキストにそのような API を使用して生成された乱数を見つけることができた場合、そのテストケースは不合格です。
