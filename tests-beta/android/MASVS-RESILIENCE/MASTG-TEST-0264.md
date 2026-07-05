---
platform: android
title: StrictMode API の実行時使用 (Runtime Use of StrictMode APIs)
id: MASTG-TEST-0264
type:
  - dynamic
  - hooks
weakness: MASWE-0094
best-practices: []
profiles:
  - R
---

# MASTG-TEST-0264 StrictMode API の実行時使用 (Runtime Use of StrictMode APIs)

### 概要

このテストは、アプリの動作を動的に解析し、`StrictMode.setVmPolicy` や `StrictMode.VmPolicy.Builder.penaltyLog` などの `StrictMode` API の使用を検出するための関連フックを配置することで、アプリが `StrictMode` を使用しているかどうかをチェックします。

`StrictMode` は開発者にとって開発時にディスク I/O やネットワーク操作などのポリシー違反をログ記録するのに役立ちますが、機密性の高い実装の詳細がログに記録され、攻撃者に悪用される可能性があります。

### 手順

1. [アプリのインストール (Installing Apps)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/android/MASTG-TECH-0005.md) を使用して、アプリをインストールします。
2. [メソッドフック (Method Hooking)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/android/MASTG-TECH-0043.md) を使用して、関連する API 呼び出しをフックします。
3. アプリを徹底的に動かして、できるだけ多くのフローをトリガーし、可能な限り機密データを入力します。

### 結果

出力には `StrictMode` API の実行時使用を示す可能性があります。

### 評価

出力が `StrictMode` API の実行時使用を示す場合、そのテストケースは不合格です。
