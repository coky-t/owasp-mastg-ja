---
platform: android
title: 外部ストレージに書き込まれたファイル (Files Written to External Storage)
id: MASTG-TEST-0200
type: [dynamic, filesystem, manual]
weakness: MASWE-0007
profiles: [L1, L2]
---

## 概要

このテストの目的は、外部ストレージ ([外部ストレージ (External Storage)](../../../knowledge/android/MASVS-STORAGE/MASTG-KNOW-0042.md)) に書き込まれたファイルを取得し、その書き込みに使用された API に関係なく、それらを検査することです。アプリの実行前と実行後にデバイスストレージからファイルを取得 ([ホストとデバイス間のデータ転送 (Host-Device Data Transfer)](../../../techniques/android/MASTG-TECH-0002.md)) するというシンプルなアプローチを使用して、アプリの実行時に作成されたファイルを特定し、それらに機密データが含まれているかどうかを確認します。

## 手順

1. [アプリのインストール (Installing Apps)](../../../techniques/android/MASTG-TECH-0005.md) を使用して、アプリをインストールします。
2. [ホストとデバイス間のデータ転送 (Host-Device Data Transfer)](../../../techniques/android/MASTG-TECH-0002.md) を使用して、外部ストレージの現在のファイルリストを取得します。
3. アプリを徹底的に動かして、できるだけ多くのフローをトリガーし、可能な限り機密データを入力します。
4. [ホストとデバイス間のデータ転送 (Host-Device Data Transfer)](../../../techniques/android/MASTG-TECH-0002.md) を使用して、外部ストレージの現在のファイルリストを再び取得します。
5. 二つのリスト間の差を算出します。

## 結果

出力にはアプリの実行時に外部ストレージ上に作成されたファイルのリストを含む可能性があります。

## 評価

上記で見つかったファイルが暗号化されておらず、機密データが漏洩している場合、テストケースは不合格です。

**さらなるバリデーションが必要となります:**

報告された各ファイルの内容を検査して、データが機密であるかどうかを判断します。

- ファイルが機密情報 (個人データ、クレデンシャル、トークンなど) を含むかどうかを判断します。
- データが暗号化なしで保存されているかどうかを判断します。
