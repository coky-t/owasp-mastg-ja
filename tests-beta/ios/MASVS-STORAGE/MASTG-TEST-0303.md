---
platform: ios
title: 共有ストレージに暗号化されていないデータを保存するための API への参照 (References to APIs for Storing Unencrypted Data in Shared Storage)
id: MASTG-TEST-0303
type: [static]
profiles: [L1, L2]
best-practices: [MASTG-BEST-0024]
weakness: MASWE-0007
knowledge: [MASTG-KNOW-0091, MASTG-KNOW-0057, MASTG-KNOW-0108]
---

## 概要

このテストは、アプリの Info.plist で `UIFileSharingEnabled` ("Application supports iTunes file sharing") キーと `LSSupportsOpeningDocumentsInPlace` ("Supports opening documents in place") キーを `YES` に設定してファイル共有を有効にすることで、共有用に構成されたアプリサンドボックス内のストレージロケーションに、アプリが暗号化されていない機密データを書き込むかどうかをチェックします。

## 手順

1. アプリバイナリに対して [radare2 for iOS](../../../tools/ios/MASTG-TOOL-0073.md) などの静的解析ツールを実行します。

2. 以下のような、共有ストレージの使用を示す API を探します。

      - [`documentDirectory`](https://developer.apple.com/documentation/foundation/filemanager/searchpathdirectory/documentdirectory) (一般的に iTunes ファイル共有 / ファイル アプリで公開されます)
      - `FileManager.default.urls(for:in:)` と `documentDirectory`
      - 書き込み操作のための `.../Documents` は以下の直接パス操作 (`Data.write(to:)`, `String.write(to:)`, `NSFileHandle`, `NSOutputStream`)

3. アプリの `Info.plist` ([アプリパッケージの探索 (Exploring the App Package)](../../../techniques/ios/MASTG-TECH-0058.md)) で `UIFileSharingEnabled` フラグと `LSSupportsOpeningDocumentsInPlace` フラグをチェックします。

## 結果

出力には以下を含む可能性があります。

- 共有ストレージに書き込む (または書き込む可能性のある) コードの場所のリスト。
- `UIFileSharingEnabled` と `LSSupportsOpeningDocumentsInPlace` の状態。

## 評価

以下の場合、そのテストは不合格です。

- アプリが暗号化されていない機密データを `documentDirectory` (または同等の共有ストレージパス) に書き込み、かつ
- `Info.plist` がユーザーに Documents ディレクトリへのアクセスを許可している (`UIFileSharingEnabled` および/または `LSSupportsOpeningDocumentsInPlace`)。

注: `documentDirectory` 自体は本質的に安全でないことはありません。リスクが発生するのは、機密データがそこに保存され、ファイル共有やファイルアプリのアクセスによって公開された場合です。対照的に、アプリサンドボックス内の他の場所 (`Library/Application Support` など) に暗号化して保存されるデータや、キーチェーンに保存されるデータは、ファイル共有が有効になってもアクセスできません。
