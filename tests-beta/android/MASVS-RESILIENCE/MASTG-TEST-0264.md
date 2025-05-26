---
platform: android
title: StrictMode API の実行時使用 (Runtime Use of StrictMode APIs)
id: MASTG-TEST-0264
type: [dynamic]
weakness: MASWE-0094
best-practices: []
status: new
---

## 概要

このテストは、アプリの動作を動的に解析し、`StrictMode.setVmPolicy` や `StrictMode.VmPolicy.Builder.penaltyLog` などの `StrictMode` API の使用を検出するための関連フックを配置することで、アプリが `StrictMode` を使用しているかどうかをチェックします。

`StrictMode` は開発者にとって開発時にディスク I/O やネットワーク操作などのポリシー違反をログ記録するのに役立ちますが、機密性の高い実装の詳細がログに記録され、攻撃者に悪用される可能性があります。

## 手順

1. 実行時メソッドフック ([メソッドフック (Method Hooking)](../../../techniques/android/MASTG-TECH-0043.md) 参照) を使用し、`StrictMode` API の使用箇所を探します。

## 結果

出力には `StrictMode` API の実行時使用を示す可能性があります。

## 評価

Frida スクリプトの出力が `StrictMode` API の実行時使用を示す場合、そのテストは不合格です。
