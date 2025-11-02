---
masvs_category: MASVS-STORAGE
platform: ios
title: UserDefaults
---

[`Preferences`](https://developer.apple.com/documentation/foundation/preferences "Preferences") API の一部である [`UserDefaults`](https://developer.apple.com/documentation/foundation/userdefaults "UserDefaults Class") クラスは、アプリ起動時にキーと値のペアを保存するためのプログラムインタフェースを提供します。これはアプリサンドボックス内の plist ファイルにデータを保存し、小規模で機密性のないデータを対象としています。

`UserDefaults` は `NSData`, `NSString`, `NSNumber`, `NSDate`, `NSArray` などの一般的な型をサポートしています。その他の型は `NSData` に変換する必要があります。

データはローカルに保存され、管理対象の教育用デバイスを除き、デバイスバックアップに含まれます。
