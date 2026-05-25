---
platform: android
title: ログ記録 API への参照 (References to Logging APIs)
id: MASTG-TEST-0231
apis: [Log, Logger, System.out.print, System.err.print, java.lang.Throwable#printStackTrace, android.util.Log]
type: [static, code]
weakness: MASWE-0001
best-practices: [MASTG-BEST-0002]
profiles: [L1, L2, P]
knowledge: [MASTG-KNOW-0049]
---

## 概要

このテストでは、アプリが `android.util.Log`, `Log`, `Logger`, `System.out.print`, `System.err.print`, `java.lang.Throwable#printStackTrace` などのログ記録 API を使用しているかどうかを検証します。

## 手順

1. [Android アプリのリバースエンジニアリング (Reverse Engineering Android Apps)](../../../techniques/android/MASTG-TECH-0013.md) を使用して、アプリをリバースエンジニアします。
2. [Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md) を使用して、関連する API を探します。

## 結果

出力にはログ記録 API が使用されている場所のリストを含む可能性があります。

## 評価

アプリが、リストされている場所のいずれかから機密情報をログ記録している場合、そのテストケースは不合格です。
