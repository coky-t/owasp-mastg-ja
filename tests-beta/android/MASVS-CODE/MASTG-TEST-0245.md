---
platform: android
title: プラットフォームバージョン API への参照 (References to Platform Version APIs)
id: MASTG-TEST-0245
apis: [Build]
type: [static]
weakness: MASWE-0077
best-practices: []
---

## 概要

このテストでは、アプリが Android オペレーティングシステムの最新バージョンで動作しているかどうかを検証します。

Kotlin では、Android アプリは現在のシステムの API レベルを返す `Build.VERSION.SDK_INT` プロパティを使用して OS バージョンを判別できます。これを Android 14 (API レベル 34) の `Build.VERSION_CODES.UPSIDE_DOWN_CAKE` などの特定のバージョン定数と比較することで、アプリは OS バージョンに基づいて条件付きでコードを実行できます。この例で、"Upside Down Cake" は Android 14 の内部コード名です。

Android アプリは、サポートする最も古い OS バージョンを定義する `minSdkVersion` を指定します。`minSdkVersion` を高くすると、ランタイムバージョンチェックの必要性が減りますが、`Build.VERSION.SDK_INT` を使用して OS バージョンを動的に検証することは依然として有益です。これにより、アプリは後方互換性を維持しながら、より新しく、より安全な機能を利用できるようになります。

## 手順

1. [Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md) で [semgrep](../../../tools/generic/MASTG-TOOL-0110.md) などのツールを使用して、オペレーティングシステムのバージョンをチェックする API を特定します。

## 結果

出力には関連する API が使用されている場所のリストを含む可能性があります。

## 評価

アプリがオペレーティングシステムのバージョンを検証するための API コールを含まない場合、そのテストは不合格です。
