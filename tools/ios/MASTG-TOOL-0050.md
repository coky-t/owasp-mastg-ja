---
title: Frida-ios-dump
platform: ios
source: https://github.com/AloneMonkey/frida-ios-dump
---

[Frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump "Frida-ios-dump") は iOS デバイスから iOS アプリ (IPA) の復号されたバージョンを取得するのに役立つ Python スクリプトです。Python 2 と Python 3 の両方をサポートしており、iOS デバイスで Frida を実行している必要があります (脱獄済みかどうかは問いません)。このツールは Frida の [Memory API](https://www.frida.re/docs/javascript-api/#memory "Frida Memory API") を使用して、実行しているアプリのメモリをダンプし、IPA ファイルを再作成します。コードはメモリから抽出されるため、自動的に復号化されます。

## 代替手段

[Bagbak](https://github.com/ChiChou/bagbak "Bagbak") は、拡張機能を含むアプリケーション全体を復号化する Node.js スクリプトです。frida-ios-dump と同じ目的を果たしますが、セットアップが簡単で、常用にはより便利であると感じるかもしれません。
