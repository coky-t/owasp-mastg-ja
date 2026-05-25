---
platform: android
title: 安全な画面ロック検出 API の実行時使用 (Runtime Use of Secure Screen Lock Detection APIs)
id: MASTG-TEST-0249
apis: [KeyguardManager, BiometricManager#canAuthenticate]
type: [dynamic, hooks]
weakness: MASWE-0008
best-practices: []
profiles: [L2]
knowledge: [MASTG-KNOW-0001]
---

## 概要

このテストは [安全な画面ロックを検出するための API への参照 (References to APIs for Detecting Secure Screen Lock)](MASTG-TEST-0247.md) と対をなす動的テストです。

この場合、`KeyguardManager.isDeviceSecure` および `BiometricManager.canAuthenticate` API の使用を探します。

## 手順

1. [アプリのインストール (Installing Apps)](../../../techniques/android/MASTG-TECH-0005.md) を使用して、アプリをインストールします。
2. [メソッドフック (Method Hooking)](../../../techniques/android/MASTG-TECH-0043.md) を使用して、関連する API 呼び出しをフックします。
3. アプリを徹底的に動かして、できるだけ多くのフローをトリガーし、可能な限り機密データを入力します。

## 結果

出力には関連する API が使用されている場所のリストを含む可能性があります。

## 評価

アプリが安全な画面ロックの存在を検証するための API を使用していない場合、そのテストケースは不合格です。
