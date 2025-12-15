---
platform: ios
title: entitlements.plist で有効になっているデバッグ可能なエンタイトルメント (Debuggable Entitlement Enabled in the entitlements.plist)
id: MASTG-TEST-0261
type: [static]
weakness: MASWE-0067
profiles: [R]
knowledge: [MASTG-KNOW-0062]
---

## 概要

このテストでは iOS アプリケーションがデバッグを許可するように設定されているかどうかを評価します。アプリがデバッグ可能な場合、攻撃者はデバッグツールを活用 ([デバッグ (Debugging)](../../../techniques/ios/MASTG-TECH-0084.md) を参照) して、アプリの実行時の動作を解析し、機密データや機能を侵害する可能性があります。

## 手順

1. [MachO バイナリからエンタイトルメントの抽出 (Extracting Entitlements from MachO Binaries)](../../../techniques/ios/MASTG-TECH-0111.md) を使用してバイナリからエンタイトルメントを抽出します。
2. `get-task-allow` キーを検索します。

## 結果

出力には `get-task-allow` エンタイトルメントの値を含みます。

## 評価

`get-task-allow` エンタイトルメントが `true` の場合、そのテストは不合格です。
