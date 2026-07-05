---
platform: android
title: アプリのサンドボックスでの暗号化していないデータの実行時保存 (Runtime Storage of Unencrypted Data in the App Sandbox)
id: MASTG-TEST-0207
type: [dynamic, filesystem]
prerequisites:
- identify-sensitive-data
weakness: MASWE-0006
profiles: [L2]
best-practices: [MASTG-BEST-0050]
knowledge: [MASTG-KNOW-0041]
---

## 概要

このテストの目的は、内部ストレージ ([内部ストレージ (Internal Storage)](../../../knowledge/android/MASVS-STORAGE/MASTG-KNOW-0041.md)) に書き込まれたファイルを取得し、その書き込みに使用された API に関係なく、それらを検査することです。アプリの実行前と実行後にデバイスストレージからファイルを取得 ([ホストとデバイス間のデータ転送 (Host-Device Data Transfer)](../../../techniques/android/MASTG-TECH-0002.md)) するというシンプルなアプローチを使用して、アプリの実行時に作成されたファイルを特定し、それらに機密データが含まれているかどうかを確認します。

## 手順

1. [アプリのインストール (Installing Apps)](../../../techniques/android/MASTG-TECH-0005.md) を使用して、アプリをインストールします。
2. [アプリデータディレクトリへのアクセス (Accessing App Data Directories)](../../../techniques/android/MASTG-TECH-0008.md) を使用して、アプリのプライベートデータディレクトリの最初のコピーをオフライン解析の参照として所持します。
3. アプリを起動して使用し、さまざまなワークフローを実行しながら、可能な限り機密データを入力します。入力したデータをメモしておくと、後でツールを使用して検索する際に、それを特定するのに役立ちます。
4. [アプリデータディレクトリへのアクセス (Accessing App Data Directories)](../../../techniques/android/MASTG-TECH-0008.md) を使用して、アプリのプライベートデータディレクトリの二つ目のコピーを所持し、最初のコピーと比較して、テストセッション時に作成または変更されたすべてのファイルを特定します。

## 結果

出力には実行時にアプリのプライベートストレージに作成されたファイルのリストを含む可能性があります。

## 評価

抽出されたファイルに機密データ (鍵、パスワード、アプリに入力された任意のデータなど) を見つけた場合、そのテストケースは不合格です。

データを評価する際には、base64 エンコーディング、16 進数表現、URL エンコーディング、エスケープシーケンス、ワイド文字、XOR などのよくあるデータ難読化手法などの方法を使用してエンコードされたデータの特定とデコードを試みます。tar や zip などの圧縮ファイルを特定して展開することも考慮してください。これらの方法は機密データをわかりにくくしますが、保護するものではありません。
