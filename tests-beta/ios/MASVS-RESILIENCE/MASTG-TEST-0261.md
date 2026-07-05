---
platform: ios
title: >-
  entitlements.plist で有効になっているデバッグ可能なエンタイトルメント (Debuggable Entitlement Enabled
  in the entitlements.plist)
id: MASTG-TEST-0261
type:
  - static
  - code
weakness: MASWE-0067
profiles:
  - R
knowledge:
  - MASTG-KNOW-0062
---

# MASTG-TEST-0261 entitlements.plist で有効になっているデバッグ可能なエンタイトルメント (Debuggable Entitlement Enabled in the entitlements.plist)

### 概要

このテストでは iOS アプリケーションがデバッグを許可するように設定されているかどうかを評価します。アプリがデバッグ可能な場合、攻撃者はデバッグツールを活用 ([デバッグ (Debugging)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0084.md) を参照) して、アプリの実行時の動作を解析し、機密データや機能を侵害する可能性があります。

### 手順

1. [アプリパッケージの探索 (Exploring the App Package)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0058.md) を使用して、アプリパッケージを unzip します。
2. [MachO バイナリからエンタイトルメントの抽出 (Extracting Entitlements from MachO Binaries)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0111.md) を使用して、メインバイナリからエンタイトルメントを抽出します。

### 結果

出力にはアプリに埋め込まれたエンタイトルメントを含む可能性があります。

### 評価

`get-task-allow` エンタイトルメントが存在し、`true` に設定されている場合、そのテストケースは不合格です。
