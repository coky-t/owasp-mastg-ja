---
title: React Native アプリのパッチ適用 (Patching React Native Apps)
platform: ios
---

[React Native](https://facebook.github.io/react-native "React Native") フレームワークを使用して開発する場合、メインのアプリケーションコードは `Payload/[APP].app/main.jsbundle` ファイルにあります。このファイルには JavaScript コードを含みます。ほとんどの場合、このファイルの JavaScript コードは minify されています。[JStillery](https://mindedsecurity.github.io/jstillery "JStillery") ツールを使用すると、このファイルの人間が読めるバージョンを再試行して、コード解析を可能になります。オンラインバージョンより [JStillery の CLI バージョン](https://github.com/mindedsecurity/jstillery/ "CLI version of JStillery") とローカルサーバーを推奨します。オンラインバージョンはサードパーティにソースを公開するためです。

iOS 10 以降では、インストール時にアプリケーションアーカイブが `/private/var/containers/Bundle/Application/[GUID]/[APP].app` フォルダにアンパックされるため、メインの JavaScript アプリケーションファイルはこの場所で変更可能です。

アプリケーションフォルダの正確な場所を特定するには [ipainstaller](../../tools/ios/MASTG-TOOL-0138.md) を使用できます。

1. `ipainstaller -l` コマンドを使用して、デバイスにインストールされているアプリケーションをリストします。出力リストから対象アプリケーションの名前を取得します。
2. `ipainstaller -i [APP_NAME]` コマンドを使用して、インストールフォルダやデータフォルダの場所など、対象アプリケーションに関する情報を表示します。
3. `Application:` で始まる行で参照されるパスを取得します。

以下の手順に従い、JavaScript ファイルにパッチ適用してください。

1. アプリケーションフォルダに移動します。
2. `Payload/[APP].app/main.jsbundle` ファイルの内容を一時ファイルにコピーします。
3. `JStillery` を使用して、一時ファイルの内容を整形し、難読化を解除します。
4. 一時ファイル内でパッチ適用すべきコードを特定し、パッチ適用します。
5. _パッチ適用したコード_ を一行にまとめ、元の `Payload/[APP].app/main.jsbundle` ファイルにコピーします。
6. アプリケーションを閉じて再起動します。
