---
title: WebView のデバッグが有効 (Debugging Enabled for WebViews)
platform: android
id: MASTG-TEST-0227
type: [static]
weakness: MASWE-0067
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

この問題を軽減するには:

- 本番では `WebView.setWebContentsDebuggingEnabled` に `false` を設定するか、不要な場合はその呼び出しを完全に削除します。
- 開発時に WebView デバッグが必要な場合は、[実行時に `ApplicationInfo.FLAG_DEBUGGABLE` フラグをチェックする](https://developer.chrome.com/docs/devtools/remote-debugging/webviews/#configure_webviews_for_debugging) ことで、アプリがデバッグ可能な状態のときのみ有効になるようにします。

例:

```kotlin
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
    if (0 != (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE))
    { WebView.setWebContentsDebuggingEnabled(true); }
}
```

**注:** この方法で WebView デバッグを無効にすると、デバイス上ですでに実行しているアプリを保護するのに役立ちます。攻撃者が WebView デバッグを悪用するには、デバイスに物理的 (盗難デバイスやテストデバイスなど) にアクセスするか、マルウェアやその他の悪意のある手段によるリモートアクセスしなければなりません。さらに、一般的にデバイスはロック解除されていなければならず、攻撃者はデバイスの PIN、パスワード、または生体認証を知っていて、完全な制御を取得し、`adb` や Chrome DevTools などのデバッグツールに接続する必要があります。

ただし、WebView デバッグを無効にしても、すべての攻撃ベクトルが排除されるわけではありません。攻撃者は以下ができるかもしれません。

1. アプリにパッチを適用してこれらの API への呼び出しを追加して ([パッチ適用 (Patching)](../../../techniques/android/MASTG-TECH-0038.md) を参照)、再パッケージして再署名します ([再パッケージと再署名 (Repackaging & Re-Signing)](../../../techniques/android/MASTG-TECH-0039.md) を参照)。
2. ランタイムメソッドフックを使用して ([メソッドフック (Method Hooking)](../../../techniques/android/MASTG-TECH-0043.md) を参照)、実行時に動的に WebView デバッグを有効にします。

WebView デバッグを無効にすることは、リスクを軽減するための防御層の一つとして機能しますが、他のセキュリティ対策と組み合わせる必要があります。
