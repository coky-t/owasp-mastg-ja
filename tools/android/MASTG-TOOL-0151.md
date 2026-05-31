---
title: debugmepLS
platform: android
source: https://github.com/sgIOlas/debugmepLS
hosts: [android]
---

[debugmepLS](https://github.com/sgIOlas/debugmepLS) は [LSPosed](MASTG-TOOL-0149.md) モジュールおよびコンパニオンアプリであり、選択した Android アプリを実行時にデバッグ可能にします。`system_server` 内のフレームワークサービスをフックして、`ApplicationInfo` とプロセス開始フラグを変更し、選択したパッケージが APK をパッチ適用や再署名することなしで `FLAG_DEBUGGABLE` を報告できるようになります。

コンパニオンアプリは、アプリごとの検索付き有効化リスト、システムアプリの切り替え、LSPosed 接続ステータスヘッダを提供します。これは動的テスト時にデバッグ不可のアプリに JDWP デバッガをアタッチする必要がある場合に便利です。

## 要件と使用上の注意

- Android 13 以降、および libxposed API を備えた LSPosed を必要とします。
- LSPosed のスコープにはシステムフレームワークを含む必要があります。
- 変更は対象アプリプロセスの再起動後に適用します。
- アプリは、他のチェックによってルート、フックフレームワーク、デバッガアタッチメントを検出する可能性が依然としてあります。

インストールと使用方法については、公式の [debugmepLS リポジトリ](https://github.com/sgIOlas/debugmepLS) を参照してください。
