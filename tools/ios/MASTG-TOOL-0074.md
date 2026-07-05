---
title: objection (iOS)
platform: ios
source: https://github.com/sensepost/objection
---

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

objection の起動は、IPA  にパッチを適用しているかどうか、frida-server が動作している脱獄済みデバイスを使用しているかどうかによって異なります。
パッチを適用した IPA を実行する場合、`-n Gadget` を使用して Gadget という名前を指定する必要があります。一方、frida-server を使用する場合、アタッチまたはスポーンしたいアプリケーションを指定する必要があります。

```bash
# Connecting to a patched IPA
$ objection -n Gadget start

# Using Frida-server
# Using frida-ps to get the correct application name
$ frida-ps -Ua | grep -i Telegram
983  Telegram

# Connecting to the Telegram app through Frida-server
$ objection -n "Telegram" start
# Alternatively use the process ID (PID)
$ objection -n 983 start

# Objection can also spawn the app through Frida-server using the application identifier / package name
$ objection --spawn -n "org.telegram.messenger"
... [usb] resume

# Alternatively with "no pause"
$ objection -s -p -n "org.telegram.messenger
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
