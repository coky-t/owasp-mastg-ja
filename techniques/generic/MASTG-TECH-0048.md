---
title: 静的解析 (Static Analysis)
platform: generic
---

# MASTG-TECH-0048 静的解析 (Static Analysis)

ホワイトボックスソースコードテストでは、Android SDK と IDE を含むテスト環境など、開発者のセットアップと同様のセットアップが必要になります。物理デバイスまたはエミュレータ (アプリのデバッグ用) へのアクセスが推奨されます。

**ブラックボックステスト** では、元の形式のソースコードにはアクセスできません。通常 [Android の APK フォーマット](https://en.wikipedia.org/wiki/Apk_\(file_format\)) のアプリケーションパッケージがあり、Android デバイスにインストールするか、[Java コードの逆コンパイル (Decompiling Java Code)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/android/MASTG-TECH-0017.md) で説明されているようにリバースエンジニアできます。
