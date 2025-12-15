---
platform: ios
title: プライベートストレージに暗号化されていないデータを保存するための API への参照 (References to APIs for Storing Unencrypted Data in Private Storage)
id: MASTG-TEST-0300
type: [static]
profiles: [L2]
best-practices: [MASTG-BEST-0024]
weakness: MASWE-0006
knowledge: [MASTG-KNOW-0091, MASTG-KNOW-0057, MASTG-KNOW-0108]
---

## 概要

このテストは、アプリが暗号化されていない機密データをプライベートストレージに書き込むかどうかをチェックします。以下に焦点を当てています。

- アプリサンドボックスディレクトリにデータを保持する API。Foundation `FileManager` メソッド、低レベルの POSIX および BSD ファイル I/O 呼び出し、`UserDefaults`、Core Data、SQLite ラッパーなどの高レベル API を含みます。
- 以下に使用されているキーチェーン API:
    - 機密データをキーチェーン内に直接保存している。
    - キーチェーンの鍵を管理している (プライベートストレージに書き込む前にデータを暗号化するために使用できます)。

## 手順

1. [radare2 for iOS](../../../tools/ios/MASTG-TOOL-0073.md) などの静的解析ツールを実行し、ファイルを作成または書き込むファイルシステム API の使用を探します。
2. [radare2 for iOS](../../../tools/ios/MASTG-TOOL-0073.md) などの静的解析ツールを実行し、キーチェーン API の使用を探します。

## 結果

出力には以下を含む可能性があります。

- アプリがプライベートストレージにデータを書き込む場所、または書き込む可能性がある場所のリスト。
- アプリがキーチェーン API を使用する場所のリスト。アクセス制御とアクセシビリティ属性を含みます。

## 評価

機密データがプライベートストレージに書き込まれる前に暗号化されていない場合、または機密データを保存するためにキーチェーン API が使用されていない場合、そのテストケースは不合格です。
