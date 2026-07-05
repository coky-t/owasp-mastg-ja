---
title: Apktool
platform: android
source: https://github.com/iBotPeaches/Apktool
---

Apktool は Android アプリパッケージ (APK) をアンパックするために使用します。標準の `unzip` ユーティリティで APK を展開するだけではいくつかのファイルが読み取れないままです。`AndroidManifest.xml` はバイナリ XML 形式にエンコードされており、テキストエディタで読み取れません。また、アプリのリソースは単一のアーカイブファイルにパッケージされたままです。

デフォルトのコマンドラインフラグで実行すると、apktool は Android Manifest ファイルをテキストベースの XML 形式に自動的にデコードし、ファイルリソースを抽出します (また、.DEX ファイルを smali コードに逆アセンブルします。この機能については本書の後半で再度説明します)。

アンパックされたファイルには、通常、以下のものがあります (`apktool d base.apk` を実行後)。

- AndroidManifest.xml: デコードされた Android Manifest ファイルです。テキストエディタで開いて編集できます。
- apktool.yml: apktool の出力に関する情報を含むファイルです。
- original: MANIFEST.MF ファイルを含むフォルダです。JAR ファイルに含まれるファイルに関する情報を含みます。
- res: アプリのリソースを含むディレクトリです。
- smali: 逆アセンブルされた Dalvik バイトコードを含むディレクトリです。

apktool を使用して、デコードしたリソースをバイナリ APK/JAR に再パッケージすることもできます。詳細と実例については、techniques の [アプリパッケージの探索](../../techniques/android/MASTG-TECH-0007.md) および [再パッケージと再署名](../../techniques/android/MASTG-TECH-0039.md) を参照してください。
