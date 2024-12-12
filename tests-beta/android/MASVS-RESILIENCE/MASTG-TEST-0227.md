---
title: WebView のデバッグが有効 (Debugging Enabled for WebViews)
platform: android
id: MASTG-TEST-0227
type: [static]
weakness: MASWE-0067
best-practices: [MASTG-BEST-0008]
---

## 概要

`WebView.setWebContentsDebuggingEnabled(true)` API はアプリケーション内の **すべて** の WebView に対してデバッグを有効にします。この機能は開発時には便利ですが、本番で有効のままにしておくと重大なセキュリティリスクをもたらします。有効にすると、接続された PC はアプリケーション内の任意の WebView 内の通信をデバッグ、盗聴、改変できます。詳細については ["Android ドキュメント"](https://developer.chrome.com/docs/devtools/remote-debugging/webviews/#configure_webviews_for_debugging) をご覧ください。

このフラグは `AndroidManifest.xml` の `debuggable` 属性とは独立して機能することに注意してください ([AndroidManifest で有効になっているデバッグフラグ (Debuggable Flag Enabled in the AndroidManifest)](MASTG-TEST-0226.md) を参照)。アプリが debuggable としてマークされていない場合でも、この API を呼び出すことで依然として WebView をデバッグできます。

## 手順

1. アプリバイナリに対して [re-flutter](../../../tools/generic/MASTG-TOOL-0100.md) などのツールで [Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md) を実行し、以下の使用箇所を探します。
    - `WebView.setWebContentsDebuggingEnabled` に `true` を設定している。
    - `ApplicationInfo.FLAG_DEBUGGABLE`

## 結果

出力には以下をリストする可能性があります。

- 実行時に `WebView.setWebContentsDebuggingEnabled` が `true` で呼び出されるすべての場所。
- `ApplicationInfo.FLAG_DEBUGGABLE` への参照。

## 評価

`WebView.setWebContentsDebuggingEnabled(true)` が無条件に呼び出される場合や、`ApplicationInfo.FLAG_DEBUGGABLE` フラグがチェックされていないコンテキストで呼び出される場合、そのテストケースは不合格です。
