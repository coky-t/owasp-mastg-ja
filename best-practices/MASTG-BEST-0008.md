---
title: WebView のデバッグが無効 (Debugging Disabled for WebViews)
alias: debugging-disabled-webviews
id: MASTG-BEST-0008
platform: android
---

攻撃者がこの機能を悪用して WebView 内の通信を盗聴、変更、デバッグすることを防ぐために、WebView デバッグが本番ビルドで無効になっていることを確認します。

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
