---
platform: android
title: StrictMode API への参照 (References to StrictMode APIs)
id: MASTG-TEST-0265
type: [static, code]
weakness: MASWE-0094
best-practices: []
profiles: [R]
---

## 概要

このテストはアプリが `StrictMode` を使用しているかどうかをチェックします。開発者にとって開発時にディスク I/O やネットワーク操作などのポリシー違反をログ記録するのに役立ちますが、機密性の高い実装の詳細がログに記録され、攻撃者に悪用される可能性があります。

## 手順

1. [Android アプリのリバースエンジニアリング (Reverse Engineering Android Apps)](../../../techniques/android/MASTG-TECH-0013.md) を使用して、アプリをリバースエンジニアします。
2. [Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md) を使用して、関連する API を探します。

## 結果

出力にはアプリ内で `StrictMode` を使用するすべてのインスタンスを特定する可能性があります。

## 評価

アプリが `StrictMode` API を使用している場合、そのテストケースは不合格です。
