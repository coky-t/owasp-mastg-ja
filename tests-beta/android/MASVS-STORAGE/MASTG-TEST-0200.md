---
platform: android
title: 外部ストレージに書き込まれたファイル (Files Written to External Storage)
id: MASTG-TEST-0200
type: [dynamic]
weakness: MASWE-0007
profiles: [L1, L2]
---

## 概要

このテストの目的は、外部ストレージ ([外部ストレージ (External Storage)](../../../knowledge/android/MASVS-STORAGE/MASTG-KNOW-0042.md)) に書き込まれたファイルを取得し、その書き込みに使用された API に関係なく、それらを検査することです。アプリの実行前と実行後にデバイスストレージからファイルを取得 ([ホストとデバイス間のデータ転送 (Host-Device Data Transfer)](../../../techniques/android/MASTG-TECH-0002.md)) するというシンプルなアプローチを使用して、アプリの実行時に作成されたファイルを特定し、それらに機密データが含まれているかどうかを確認します。

## 手順

1. [adb](../../../tools/android/MASTG-TOOL-0004.md) がインストールされていることを確認します。
2. アプリをインストールします ([アプリのインストール (Installing Apps)](../../../techniques/android/MASTG-TECH-0005.md))。
3. アプリを実行する前に、外部ストレージの現在のファイルリストを取得します ([ホストとデバイス間のデータ転送 (Host-Device Data Transfer)](../../../techniques/android/MASTG-TECH-0002.md))。
4. アプリを実行します。
5. アプリを実行した後、外部ストレージのファイルリストを再度取得します。
6. 二つのリスト間の差を算出します。

## 結果

出力にはアプリの実行時に外部ストレージ上に作成されたファイルのリストを含む可能性があります。

## 評価

上記で見つかったファイルが暗号化されておらず、機密データが漏洩している場合、テストケースは不合格です。

これを確認するには、アプリをリバースエンジニア ([Java コードの逆コンパイル (Decompiling Java Code)](../../../techniques/android/MASTG-TECH-0017.md)) して、コードを調査 ([逆コンパイルした Java コードのレビュー (Reviewing Decompiled Java Code)](../../../techniques/android/MASTG-TECH-0023.md)) します。
