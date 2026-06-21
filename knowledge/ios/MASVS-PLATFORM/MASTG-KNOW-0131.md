---
masvs_category: MASVS-PLATFORM
platform: ios
title: Core NFC (Core NFC)
available_since: 11
---

[Core NFC](https://developer.apple.com/documentation/corenfc) は NFC (Near Field Communication) タグを読み書きするための iOS フレームワークです。アプリは主にこれを使用して、製品ラベル、交通系カード、スマートポスターなどの物理的な物体に埋め込まれた NFC タグを読み取ります。

## API

Core NFC は一般に使用される二つのタグ読み取りセッションクラスを提供します。

- **[`NFCNDEFReaderSession`](https://developer.apple.com/documentation/corenfc/nfcndefreadersession)**: NFC タグから NDEF レコードを読み取ります。NDEF タグ書き込みサポートは iOS 13 で追加されました。
- **[`NFCTagReaderSession`](https://developer.apple.com/documentation/corenfc/nfctagreadersession)**: ISO 7816, ISO 15693, FeliCa, MIFARE などの特定のタグタイプへの低レベルアクセスを提供します。iOS 13 以降で利用可能です。

## パーミッションとエンタイトルメント

アプリは `Info.plist` に [`NFCReaderUsageDescription`](https://developer.apple.com/documentation/bundleresources/information_property_list/nfcreaderusagedescription) を宣言する必要があります。`NFCTagReaderSession` を通じてのアクセスには、Xcode の Near Field Communication タグ読み取り機能を通じて有効化される [`com.apple.developer.nfc.readersession.formats`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.nfc.readersession.formats) エンタイトルメントを必要とします。

一部のタグ技法では、ISO 7816 アプリケーション識別子用の [`com.apple.developer.nfc.readersession.iso7816.select-identifiers`](http://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.nfc.readersession.iso7816.select-identifiers) や FeliCa システムコード用の [`com.apple.developer.nfc.readersession.felica.systemcodes`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.nfc.readersession.felica.systemcodes) など、追加の `Info.plist` キーを必要とします。
