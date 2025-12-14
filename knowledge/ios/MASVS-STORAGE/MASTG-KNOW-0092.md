---
masvs_category: MASVS-STORAGE
platform: ios
title: バイナリデータストレージ (Binary Data Storage)
---

`NSData` (静的データオブジェクト) と `NSMutableData` (動的データオブジェクト) は一般的にデータストレージに対して使用されますが、データオブジェクトに含まれるデータがアプリケーション間でコピーまたは移動できる分散オブジェクトアプリケーションにも役立ちます。

[`write(to:options:)`](https://developer.apple.com/documentation/Foundation/Data/write(to:options:)) を使用して `NSData` オブジェクトを書き込む際に、ファイル保護のために [`WritingOptions`](https://developer.apple.com/documentation/foundation/nsdata/writingoptions) を指定できます。

- `noFileProtection`: ファイルを暗号化しません。
- `completeFileProtection`: ファイルが暗号化され、デバイスがアンロックされている場合にのみアクセスできるようにします。
- `completeFileProtectionUnlessOpen`: ファイルが暗号化され、デバイスがアンロックされている場合またはファイルが既に開かれている場合にのみアクセスできるようにします。
- `completeFileProtectionUntilFirstUserAuthentication`: ファイルが暗号化され、再起動後の最初のユーザー認証後にのみアクセスできるようにします。
