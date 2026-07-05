---
title: WebView でのファイルシステム操作の監視 (Monitor File System Operations in WebViews)
platform: android
---

さまざまな技法を使用して WebView ストレージディレクトリのファイルシステム操作を監視できます。

[メソッドトレース (Method Tracing)](MASTG-TECH-0033.md) を使用して、`/data/data/<app_package>/app_webview/` ディレクトリのファイルシステム操作を監視します。アプリがこれらの API を直接使用しているかどうかに関係なく、WebView はコンテンツを描画する際に内部的に使用することがあります (例: `localStorage` を使用する JavaScript コード)。そのため `open`, `openat`, `opendir`, `unlinkat` などの API への呼び出しをトレースすると、WebView ストレージディレクトリのファイル操作を特定するのに役立ちます。

メソッドコールをトレースすることに加えて、以下のすべてのファイル操作も監視できます。

- [オープンファイルの取得 (Get Open Files)](MASTG-TECH-0027.md) を使用して、そのディレクトリのファイル操作を監視します。例: `lsof -p <app_pid> | grep /app_webview/`
- または [実行トレース (Execution Tracing)](MASTG-TECH-0032.md) を使用して (例: `strace -p <app_pid>`)、そのディレクトリのファイル操作を監視します。
