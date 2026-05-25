---
platform: android
title: 外部ストレージにアクセスするための API の実行時使用 (Runtime Use of APIs to Access External Storage)
id: MASTG-TEST-0201
apis: [Environment#getExternalStorageDirectory, Environment#getExternalStorageDirectory, Environment#getExternalFilesDir, Environment#getExternalCacheDir, FileOutputStream]
type: [dynamic, hooks, manual]
weakness: MASWE-0007
profiles: [L1, L2]
knowledge: [MASTG-KNOW-0042]
---

## 概要

Android アプリは外部ストレージ ([外部ストレージ (External Storage)](../../../knowledge/android/MASVS-STORAGE/MASTG-KNOW-0042.md)) にアクセスするのにさまざまな API を使用します。これらの API の包括的なリストを収集するのは、特にアプリがサードパーティフレームワークを使用したり、実行時にコードをロードしたり、ネイティブコードを含む場合、困難なことがあります。

デバイスストレージに書き込むアプリケーションをテストする最も効果的なアプローチは、一般的に、動的解析、特にメソッドフックです。`getExternalStorageDirectory`, `getExternalStoragePublicDirectory`, `getExternalFilesDir`, `FileOutPutStream` などの関連する API にフックできます。またファイル操作全般を捕捉する `open` を使用できます。しかし、これは、`MediaStore` API を使用するものなど、すべてのファイル操作を捕捉するわけではなく、多くのノイズを発生する可能性があるため、追加のフィルタリングを行う必要があります。

## 手順

1. [アプリのインストール (Installing Apps)](../../../techniques/android/MASTG-TECH-0005.md) を使用して、アプリをインストールします。
2. [メソッドフック (Method Hooking)](../../../techniques/android/MASTG-TECH-0043.md) を使用して、関連する API 呼び出しをフックします。
3. アプリを徹底的に動かして、できるだけ多くのフローをトリガーし、可能な限り機密データを入力します。

## 結果

出力にはアプリが実行時に外部ストレージに書き込んだファイルのリストと、関数名やバックトレースを含む、それらの書き込みに使用された API を含む可能性があります。

## 評価

上記で見つかったファイルが暗号化されておらず、機密データが漏洩している場合、テストケースは不合格です。

**さらなるバリデーションが必要となります:**

報告された各ファイルの内容を検査して、データが機密であるかどうかを判断します。

- ファイルが機密情報 (個人データ、クレデンシャル、トークンなど) を含むかどうかを判断します。
- データが暗号化なしで保存されているかどうかを判断します。

ファイル作成につながる正確なコードパスを特定し、それらがセキュリティ上重要であるかどうかを望む場合には、[逆コンパイルされた Java コードのレビュー (Reviewing Decompiled Java Code)](../../../techniques/android/MASTG-TECH-0023.md) を使用して、バックトレースからのコード箇所を検査します。
