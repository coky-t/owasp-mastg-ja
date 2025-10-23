---
title: objection for iOS
platform: ios
source: https://github.com/sensepost/objection
---

### ??? 情報 "objection についての情報"

以下のコマンドは、Frida < 17 に依存する objection バージョン 1.11.0 のものです。objection を使用するには、`frida-tools==13.7.1` をインストールし、デバイスで 17 未満の `frida-server` を使用します。Frida 17 で objection を使用したい場合、objection リポジトリから最新バージョンを取得してローカルでビルドできます。いくつかのコマンドは以降のリリースで変更されているため、以下の手順を変更する必要があることに注意してください。たとえば、objection バージョン 2 では、API `explore` コマンドは `start` に置き換えられることが期待されています。更新バージョンが正式にリリースされた後、以下の手順は更新されるでしょう。

objection は iOS に特化した機能をいくつか提供しています。[機能の全リスト](https://github.com/sensepost/objection/wiki/Features) はプロジェクトのページにありますが、ここでは興味深いものをいくつか紹介します。

- アプリケーションを再パッケージして Frida ガジェットを含めます
- 一般的な方法での SSL ピン留めを無効にします
- アプリケーションストレージにアクセスして、ファイルをダウンロードまたはアップロードします
- カスタム Frida スクリプトを実行します
- キーチェーンをダンプします
- plist ファイルを読み取ります

これらのすべてのタスクやその他のことは objection の REPL のコマンドを使用して簡単に実行できます。たとえば、以下を実行して、アプリで使用されているクラス、クラスの関数、アプリのバンドルに関する情報を取得できます。

```bash
$ ios hooking list classes
$ ios hooking list class_methods <ClassName>
$ ios bundles list_bundles
```

frida-server をインストールした脱獄済みデバイスがある場合、objection は実行中の Frida サーバーに直接接続して、アプリケーションを再パッケージする必要なくすべての機能を提供できます。しかし、iOS の最新バージョンを脱獄することが常に可能であるとは限りませんし、高度な脱獄検出メカニズムを備えたアプリケーションを持っているかもしれません。

**脱獄されていないデバイスで高度な動的解析を実行する** 能力は objection を非常に便利にする機能の一つです。再パッケージ化のプロセス ([再パッケージ化と再署名 (Repackaging & Re-Signing)](../../techniques/ios/MASTG-TECH-0092.md)) に従うと、前述のコマンドをすべて実行できるようになり、アプリケーションを素早く解析したり、基本的なセキュリティコントロールを回避することが非常に簡単になります。

## iOS で objection を使用する

objection の起動は、IPA  にパッチを適用しているかどうか、frida-server が動作している脱獄済みデバイスを使用しているかどうかによって異なります。パッチを適用した IPA を実行する場合、objection は接続されているデバイスを自動的に検出し、リッスンしている Frida ガジェットを探します。しかし、frida-server を使用する場合、解析したいアプリケーションを frida-server に明示的に伝える必要があります。

```bash
# Connecting to a patched IPA
$ objection explore

# Using frida-ps to get the correct application name
$ frida-ps -Ua | grep -i Telegram
983  Telegram

# Connecting to the Telegram app through Frida-server
$ objection --gadget="Telegram" explore
```

objection REPL に入ると、利用可能な任意のコマンドを実行できます。以下は最も便利ないくつかのコマンドの概要です。

```bash
# Show the different storage locations belonging to the app
$ env

# Disable popular ssl pinning methods
$ ios sslpinning disable

# Dump the Keychain
$ ios keychain dump

# Dump the Keychain, including access modifiers. The result will be written to the host in myfile.json
$ ios keychain dump --json <myfile.json>

# Show the content of a plist file
$ ios plist cat <myfile.plist>

```

objection REPL の使用に関する詳細は [objection Wiki](https://github.com/sensepost/objection/wiki/Using-objection "Using Objection") にあります。
