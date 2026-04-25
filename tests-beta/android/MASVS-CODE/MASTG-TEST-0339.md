---
title: コンテンツプロバイダでの SQL インジェクション (SQL Injection in Content Providers)
platform: android
id: MASTG-TEST-0339
type: [static]
weakness: MASWE-0086
best-practices: [MASTG-BEST-0039]
profiles: [L1, L2]
knowledge: [MASTG-KNOW-0117]
---

## 概要

Android アプリケーションは `ContentProvider` コンポーネントを介して構造化データを共有できます。しかし、これらのプロバイダが、適切なバリデーションやパラメータ化なしで、信頼できない URL からの入力を使用して SQL クエリを作成すると、SQL インジェクション攻撃に影響を受けやすくなるリスクがあります。

## 手順

1. アプリをリバースエンジニアします ([Android アプリのリバースエンジニアリング (Reverse Engineering Android Apps)](../../../techniques/android/MASTG-TECH-0013.md))。
2. 静的解析 ([Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md)) を実行して、ContentProvider 内の安全でない SQL 構文を探します。

## 結果

出力には、URI または選択引数からのユーザー制御入力が、たとえば `Uri.getPathSegments()` および `SQLiteQueryBuilder.appendWhere()` を介して SQL クエリに連結される場所のリストを含む可能性があります。

## 評価

以下の場合、そのテストケースは不合格です。

- 信頼できないユーザー入力 (例: `getPathSegments()` から) が SQL 文に直接連結されている。
- アプリが `appendWhere()` を使用しているか、サニタイゼーションやパラメータ化なしで安全でないクエリを構築している。
