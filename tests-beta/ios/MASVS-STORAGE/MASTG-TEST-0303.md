---
platform: ios
title: 共有ストレージに暗号化されていないデータを保存するための API への参照 (References to APIs for Storing Unencrypted Data in Shared Storage)
id: MASTG-TEST-0303
type: [static, code]
profiles: [L1, L2]
best-practices: [MASTG-BEST-0024]
weakness: MASWE-0007
knowledge: [MASTG-KNOW-0091, MASTG-KNOW-0057, MASTG-KNOW-0108]
---

## 概要

このテストは、アプリが機密データを暗号化せずに iOS のサイドボックス内の場所に保存し、ファイル共有が有効になった際にユーザーがアクセスできる可能性があるかどうかをチェックします。

iOS では、アプリのサンドボックスはデフォルトではプライベートです。しかし、アプリが `Info.plist` で [`UIFileSharingEnabled`](https://developer.apple.com/documentation/bundleresources/information-property-list/uifilesharingenabled) または [`LSSupportsOpeningDocumentsInPlace`](https://developer.apple.com/documentation/bundleresources/information-property-list/lssupportsopeningdocumentsinplace) を `YES` に設定すると、特定のサンドボックスの場所、特に [`documentDirectory`](https://developer.apple.com/documentation/foundation/filemanager/searchpathdirectory/documentdirectory) にあるファイルが、Finder、iTunes ファイル共有またはファイルアプリを通じてアクセスできるようになることがあります。

[`documentDirectory`](https://developer.apple.com/documentation/foundation/filemanager/searchpathdirectory/documentdirectory), [`URL.documentsDirectory`](https://developer.apple.com/documentation/foundation/url/documentsdirectory), または実行時に解決される同等のパスなど、共有ストレージまたは共有される可能性のあるストレージ場所にファイルを作成、変更、永続化する API がアプリにないかレビューします。関連する API には [`FileManager`](https://developer.apple.com/documentation/foundation/filemanager), [`Data.write(to:)`](https://developer.apple.com/documentation/foundation/data/write%28to:options:%29), [`String.write(to:atomically:encoding:)`](https://developer.apple.com/documentation/swift/string/write%28to:atomically:encoding:%29), [`FileHandle`](https://developer.apple.com/documentation/foundation/filehandle), [`OutputStream`](https://developer.apple.com/documentation/foundation/outputstream) のほか、`open`, `write`, `fwrite`, `fputs` などの低レベル POSIX または BSD ファイル I/O 関数を含みます。

また、アプリが機密データをこれらの場所に書き込む前に保護しているかどうかをレビューします。たとえば、アプリはキーチェーンに保存されているキーを使用してデータを暗号化することがあります。[`SecItemAdd`](https://developer.apple.com/documentation/security/secitemadd%28_:_:%29), [`SecItemUpdate`](https://developer.apple.com/documentation/security/secitemupdate%28_:_:%29), [`SecItemCopyMatching`](https://developer.apple.com/documentation/security/secitemcopymatching%28_:_:%29) などのキーチェーン API 使用によって、暗号鍵が適切なアクセス制御とアクセスビリティ属性で作成、取得、保護されているかどうかを判断できます。

## 手順

1. [アプリパッケージの探索 (Exploring the App Package)](../../../techniques/ios/MASTG-TECH-0058.md) を使用して、アプリパッケージから関連するバイナリを抽出します。
2. [iOS での静的解析 (Static Analysis on iOS)](../../../techniques/ios/MASTG-TECH-0066.md) を使用して、アプリバイナリ内の関連する API を探します。
3. [Info.plist ファイルの取得 (Retrieving Info.plist Files)](../../../techniques/ios/MASTG-TECH-0153.md) を使用して、`Info.plist` ファイルを取得します。
4. [Info.plist ファイルの解析 (Analyzing Info.plist Files)](../../../techniques/ios/MASTG-TECH-0154.md) を使用して、`UIFileSharingEnabled` および `LSSupportsOpeningDocumentsInPlace` フラグをチェックします。

## 結果

出力には以下を含む可能性があります。

- 共有ストレージに書き込む (または書き込む可能性のある) コードの場所のリスト。
- `UIFileSharingEnabled` と `LSSupportsOpeningDocumentsInPlace` の状態。

## 評価

以下の場合、そのテストケースは不合格です。

- アプリが暗号化されていない機密データを `documentDirectory` (または同等の共有ストレージパス) に書き込み、かつ
- `Info.plist` がユーザーに Documents ディレクトリへのアクセスを許可している (`UIFileSharingEnabled` および/または `LSSupportsOpeningDocumentsInPlace`)。

注: `documentDirectory` 自体は本質的に安全でないことはありません。リスクが発生するのは、機密データがそこに保存され、ファイル共有やファイルアプリのアクセスによって公開された場合です。対照的に、アプリサンドボックス内の他の場所 (`Library/Application Support` など) に暗号化して保存されるデータや、キーチェーンに保存されるデータは、ファイル共有が有効になってもアクセスできません。
