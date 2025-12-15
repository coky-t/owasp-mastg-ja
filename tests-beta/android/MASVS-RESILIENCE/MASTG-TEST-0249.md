---
platform: android
title: 安全な画面ロック検出 API の実行時使用 (Runtime Use of Secure Screen Lock Detection APIs)
id: MASTG-TEST-0249
apis: [KeyguardManager, BiometricManager#canAuthenticate]
type: [dynamic]
weakness: MASWE-0008
best-practices: []
profiles: [L2]
knowledge: [MASTG-KNOW-0001]
---

## 概要

このテストは [安全な画面ロックを検出するための API への参照 (References to APIs for Detecting Secure Screen Lock)](MASTG-TEST-0247.md) と対をなす動的テストです。

## 手順

1. [Frida for Android](../../../tools/android/MASTG-TOOL-0001.md) などの動的解析ツールを実行して、`KeyguardManager.isDeviceSecure` と `BiometricManager.canAuthenticate` の API の使用を探します。

## 結果

出力には関連する API が使用されている場所のリストを含む可能性があります。

## 評価

アプリが安全な画面ロックの存在を検証するための API を使用していない場合、そのテストは不合格です。
