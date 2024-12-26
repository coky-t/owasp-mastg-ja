---
title: 静的解析 (Static Analysis)
platform: generic
---

ホワイトボックスソースコードテストでは、Android SDK と IDE を含むテスト環境など、開発者のセットアップと同様のセットアップが必要になります。物理デバイスまたはエミュレータ (アプリのデバッグ用) へのアクセスが推奨されます。

**ブラックボックステスト** では、元の形式のソースコードにはアクセスできません。通常 [Android の APK フォーマット](https://en.wikipedia.org/wiki/Apk_(file_format) "APK file format") のアプリケーションパッケージがあり、Android デバイスにインストールするか、「[Java コードの逆コンパイル (Decompiling Java Code)](../../techniques/android/MASTG-TECH-0017.md)」で説明されているようにリバースエンジニアできます。
