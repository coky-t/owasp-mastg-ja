---
platform: android
title: 実行時にアプリのサンドボックスに保存されるデータ (Data Stored in the App Sandbox at Runtime)
id: MASTG-TEST-0207
type: [dynamic, filesystem]
prerequisites:
- identify-sensitive-data
weakness: MASWE-0006
profiles: [L2]
---

## 概要

このテストの目的は、[内部ストレージ](../../../0x05d-Testing-Data-Storage.md/#internal-storage) に書き込まれたファイルを取得し、その書き込みに使用された API に関係なく、それらを検査することです。アプリの実行前と実行後にデバイスストレージからファイルを取得 ([ホストとデバイス間のデータ転送 (Host-Device Data Transfer)](../../../techniques/android/MASTG-TECH-0002.md)) するというシンプルなアプローチを使用して、アプリの実行時に作成されたファイルを特定し、それらに機密データが含まれているかどうかを確認します。

## 手順

1. デバイスを起動します。

2. アプリのプライベートデータディレクトリの最初のコピーを作成 ([アプリデータディレクトリへのアクセス (Accessing App Data Directories)](../../../techniques/android/MASTG-TECH-0008.md)) し、オフライン解析の参照として所持します。たとえば [adb](../../../tools/android/MASTG-TOOL-0004.md) を使用できます。

3. アプリを起動して使用し、さまざまなワークフローを実行しながら、可能な限り機密データを入力します。入力したデータをメモしておくと、後でツールを使用して検索する際に、それを特定するのに役立ちます。

4. アプリのプライベートデータディレクトリの二つ目のコピーをオフライン解析用に作成し、最初のコピーを使用して差分を作成し、テストセッション時に作成または変更されたすべてのファイルを特定します。

## 結果

出力には実行時にアプリのプライベートストレージに作成されたファイルのリストを含む可能性があります。

## 評価

base64 エンコーディング、16 進数表現、URL エンコーディング、エスケープシーケンス、ワイド文字、XOR などのよくあるデータ難読化手法などの方法を使用してエンコードされたデータの特定とデコードを試みます。tar や zip などの圧縮ファイルを特定して展開することも考慮してください。これらの方法は機密データをわかりにくくしますが、保護するものではありません。

抽出されたデータから鍵、パスワード、アプリに入力された任意の機密データなどのアイテムを探します。このような機密データを見つけることができた場合、そのテストケースは不合格です。
