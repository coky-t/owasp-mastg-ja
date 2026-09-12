---
title: バンドルされているネイティブライブラリの抽出 (Extracting Bundled Native Libraries)
platform: android
---

この技法は、静的解析を使用して (アプリを実行せずに)、Android アプリの APK 内にパッケージ化されているネイティブライブラリ (`.so` ファイル) を特定する方法を説明します。ネイティブライブラリは APK の `lib/` ディレクトリに格納されており、CPU アーキテクチャ (ABI) によって分類されています。

すでに [Java コードの逆コンパイル (Decompiling Java Code)](MASTG-TECH-0017.md) を使用してアプリを逆コンパイルしている場合、すでにネイティブライブラリを抽出している可能性があります。逆コンパイルされた出力で `lib/` ディレクトリを探してみます。

## `unzip` を使用する

APK は ZIP アーカイブです。標準的なツールでそれを抽出して、`lib/` ディレクトリにネイティブライブラリをリストできます。

```bash
unzip -o YourApp.apk "lib/*" -d YourApp
find YourApp/lib -name "*.so"
YourApp/lib/arm64-v8a/libnative-lib.so
YourApp/lib/armeabi-v7a/libnative-lib.so
...
```

## [Apktool](../../tools/android/MASTG-TOOL-0011.md) を使用する

[Apktool](../../tools/android/MASTG-TOOL-0011.md) は APK をアンパックして、ディレクトリ構造を維持しており、`lib/` フォルダを調査することが容易になります。

```bash
apktool d YourApp.apk -o YourApp
ls -1 YourApp/lib/arm64-v8a/
libnative-lib.so
libsqlcipher.so
...
```
