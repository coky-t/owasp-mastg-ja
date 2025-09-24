---
title: objection for Android
platform: android
source: https://github.com/sensepost/objection
---

objection は Android に特化した機能をいくつか提供しています。[機能の全リスト](https://github.com/sensepost/objection/wiki/Features) はプロジェクトのページにありますが、ここでは興味深いものをいくつか紹介します。

- アプリケーションを再パッケージして Frida ガジェットを含めます
- 一般的な方法での SSL ピン留めを無効にします
- アプリケーションストレージにアクセスして、ファイルをダウンロードまたはアップロードします
- カスタム Frida スクリプトを実行します
- アクティビティ、サービス、ブロードキャストレシーバをリストします
- アクティビティを開始します

frida-server をインストールしたルート化済みデバイスがある場合、objection は実行中の Frida サーバーに直接接続して、アプリケーションを再パッケージする必要なくすべての機能を提供できます。しかし、Android デバイスをルート化することが常に可能であるとは限らず、アプリにルート検出のための高度な RASP コントロールを含むこともあるため、frida-gadget を注入することがそのコントロールをバイパスする最も簡単な方法であるかもしれません。

**ルート化されていないデバイスで高度な動的解析を実行する** 能力は objection を非常に便利にする機能の一つです。再パッケージ化のプロセス ([再パッケージ化と再署名 (Repackaging & Re-Signing)](../../techniques/android/MASTG-TECH-0039.md)) に従うと、前述のコマンドをすべて実行できるようになり、アプリケーションを素早く解析したり、基本的なセキュリティコントロールをバイパスすることが非常に簡単になります。

## Android で objection を使用する

objection の起動は、APK にパッチを適用しているかどうか、frida-server が動作しているルート化済みデバイスを使用しているかどうかによって異なります。パッチを適用した APK を実行する場合、objection は接続されているデバイスを自動的に検出し、リッスンしている Frida ガジェットを探します。しかし、frida-server を使用する場合、解析したいアプリケーションを frida-server に明示的に伝える必要があります。

```bash
# Connecting to a patched APK
objection explore

# Find the correct name using frida-ps
$ frida-ps -Ua | grep -i telegram
30268  Telegram                               org.telegram.messenger

# Connecting to the Telegram app through Frida-server
$ objection --gadget="org.telegram.messenger" explore
```

objection REPL に入ると、利用可能な任意のコマンドを実行できます。以下は最も便利ないくつかのコマンドの概要です。

```bash
# Show the different storage locations belonging to the app
$ env

# Disable popular SSL pinning methods
$ android sslpinning disable

# List items in the keystore
$ android keystore list

# Try to circumvent root detection
$ android root disable

```

objection REPL の使用に関する詳細は [objection Wiki](https://github.com/sensepost/objection/wiki/Using-objection "Using Objection") にあります。
