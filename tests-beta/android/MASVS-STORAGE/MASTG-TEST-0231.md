---
platform: android
title: ログ記録 API への参照 (References to Logging APIs)
id: MASTG-TEST-0231
apis: [Log, Logger, System.out.print, System.err.print, java.lang.Throwable#printStackTrace, android.util.Log]
type: [static]
weakness: MASWE-0001
best-practices: [MASTG-BEST-0002]
---

## 概要

このテストでは、アプリが `android.util.Log`, `Log`, `Logger`, `System.out.print`, `System.err.print`, `java.lang.Throwable#printStackTrace` などの [ログ記録 API](../../../0x05d-Testing-Data-Storage.md/#logs) を使用しているかどうかを検証します。

## 手順

1. [Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md) を [semgrep](../../../tools/generic/MASTG-TOOL-0110.md) などのツールとともに使用して、すべてのログ記録 API を特定します。

## 結果

出力にはログ記録 API が使用されている場所のリストを含む可能性があります。

## 評価

アプリが、リストされている場所のいずれかから機密情報をログ記録している場合、そのテストは不合格です。
