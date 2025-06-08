---
platform: android
title: 外部ストレージにアクセスするための API の実行時使用 (Runtime Use of APIs to Access External Storage)
id: MASTG-TEST-0201
apis: [Environment#getExternalStorageDirectory, Environment#getExternalStorageDirectory, Environment#getExternalFilesDir, Environment#getExternalCacheDir, FileOutputStream]
type: [dynamic]
weakness: MASWE-0007
profiles: [L1, L2]
---

## 概要

Android アプリは [外部ストレージにアクセスするのにさまざまな API](../../../0x05d-Testing-Data-Storage.md/#external-storage-apis) を使用します。これらの API の包括的なリストを収集するのは、特にアプリがサードパーティフレームワークを使用したり、実行時にコードをロードしたり、ネイティブコードを含む場合、困難なことがあります。デバイスストレージに書き込むアプリケーションをテストする最も効率的なアプローチは、通常、動的解析、具体的にはメソッドトレース ([メソッドトレース (Method Tracing)](../../../techniques/android/MASTG-TECH-0033.md)) です。

## 手順

1. [Frida for Android](../../../tools/android/MASTG-TOOL-0001.md) がインストールされていることを確認します。
2. アプリをインストールします。
3. スクリプトを実行して、Frida でアプリを起動し、ファイルとのすべてのやり取りをログ記録します。
4. 解析したいアプリの画面に遷移します。
5. アプリを閉じて Frida を停止します。

Frida スクリプトは `getExternalStorageDirectory`, `getExternalStoragePublicDirectory`, `getExternalFilesDir`, `FileOutPutStream` などの関連する API にフックして、すべてのファイル操作をログ記録する必要があります。また `open` をファイル操作の包括的なものとして使用することもできます。しかし、`MediaStore` API を使用するものなど、すべてのファイル操作を捕捉するわけではなく、大量のノイズが発生する可能性があるため、追加のフィルタリングを行う必要があります。

## 結果

出力にはアプリが実行時に外部ストレージに書き込んだファイルのリストと、可能であれば、それらの書き込みに使用された API を含む可能性があります。

## 評価

上記で見つかったファイルが暗号化されておらず、機密データが漏洩している場合、テストケースは不合格です。

これを確認するには、adb シェルを使用 ([ホストとデバイス間のデータ転送 (Host-Device Data Transfer)](../../../techniques/android/MASTG-TECH-0002.md)) してデバイスからそれらを取得し、ファイルを手作業で検査し、アプリをリバースエンジニア ([Java コードの逆コンパイル (Decompiling Java Code)](../../../techniques/android/MASTG-TECH-0017.md)) して、コードを調査 ([逆コンパイルした Java コードのレビュー (Reviewing Decompiled Java Code)](../../../techniques/android/MASTG-TECH-0023.md)) します。
