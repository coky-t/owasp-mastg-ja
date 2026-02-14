---
title: LSPosed
platform: android
source: https://github.com/JingMatrix/LSPosed
---

LSPosed は、Android アプリケーションパッケージ (APK) を変更したり再フラッシュしたりすることなく、実行時にシステムまたはアプリケーションの側面と動作を変更できる Zygisk モジュールです。技術的には、これは Zygote の拡張バージョンであり、新しいプロセスが開始された際に Java コードを実行するための API をエクスポートします。新しくインスタンス化されたアプリのコンテキストで Java コードを実行すると、アプリに属する Java メソッドを解決、フック、オーバーライドできるようになります。
