---
title: Info.plist ファイルの取得 (Retrieving Info.plist Files)
platform: ios
---

`Info.plist` ファイルはすべての iOS アプリバンドルに含まれる主要なプロパティリスト設定ファイルです。これには、パーミッション、ケイパビリティ、App Transport Security (ATS) などのセキュリティ設定を含む、アプリの構成を記述したキーと値のペアを含みます。

[アプリパッケージの探索 (Exploring the App Package)](MASTG-TECH-0058.md) でアプリを抽出した後、`.app` バンドルのルートにある `Info.plist` ファイルを見つけることができます。たとえば、[アプリパッケージの探索 (Exploring the App Package)](MASTG-TECH-0058.md) を使用して `MyApp.ipa` という名前の iOS アプリを抽出した場合、`Payload/` フォルダから以下のコマンドを実行できます。

```sh
find . -name "Info.plist" -maxdepth 2

./MyApp.app/Info.plist
```

`-maxdepth 2` フラグはその検索をアプリバンドルのルートに限定し、ネストされたフレームワークや拡張から `Info.plist` ファイルをリストすることを避けます。フレームワークや拡張を調査する必要もある場合には、深さを増すか、その制限を解除します。

App Store を通じて配信されるアプリは一般的にバイナリ plist 形式で `Info.plist` を出荷します。そのファイルがバイナリ形式である場合、それを調査する前に [Plist ファイルを JSON に変換する (Convert Plist Files to JSON)](MASTG-TECH-0138.md) を使用して人間が読み取り可能な形式に変換するか、[Info.plist ファイルの解析 (Analyzing Info.plist Files)](MASTG-TECH-0154.md) を使用してそれを直接解析します。
