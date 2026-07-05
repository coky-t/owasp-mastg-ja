---
platform: ios
title: iOS の汎用ペーストボードの使用 (Use of the iOS General Pasteboard)
id: MASTG-TEST-0276
type:
  - static
  - code
  - manual
weakness: MASWE-0053
threat:
  - app
prerequisites:
  - identify-sensitive-data
profiles:
  - L2
knowledge:
  - MASTG-KNOW-0083
---

# MASTG-TEST-0276 iOS の汎用ペーストボードの使用 (Use of the iOS General Pasteboard)

### 概要

このテストはアプリがシステム全体で汎用 [ペーストボード (Pasteboard)](https://github.com/coky-t/owasp-mastg-ja/blob/master/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0083.md) を使用しているかどうかをチェックします。これはデバイスの再起動やアプリのアンインストール後も永続的に保持され、すべてのフォアグラウンドアプリや、場合によっては他のデバイスからもアクセスできます。ここに機密データを置くと、プライバシーリスクを引き起こすかもしれません。

このテストは汎用ペーストボード ([`UIPasteboard.general`](https://developer.apple.com/documentation/uikit/uipasteboard/general)) を使用するコードを静的に解析し、機密データが以下のメソッドのいずれかを使用して書き込まれているかどうかをチェックします。

* [`addItems`](https://developer.apple.com/documentation/uikit/uipasteboard/additems\(_:\))
* [`setItems`](https://developer.apple.com/documentation/uikit/uipasteboard/setitems\(_:options:\))
* [`setData`](https://developer.apple.com/documentation/uikit/uipasteboard/setdata\(_:forpasteboardtype:\))
* [`setValue`](https://developer.apple.com/documentation/uikit/uipasteboard/setvalue\(_:forpasteboardtype:\))

### 手順

1. [アプリパッケージの探索 (Exploring the App Package)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0058.md) を使用して、アプリパッケージから関連するバイナリを抽出します。
2. [iOS での静的解析 (Static Analysis on iOS)](../../../techniques/ios/MASTG-TECH-0066.md) を使用して、アプリバイナリ内の関連する API を探します。

### 結果

出力には関連する API が使用されている場所のリストを含む可能性があります。

### 評価

`UIPasteboard.generalPasteboard` への呼び出しが行われ、機密データがそこに書き込まれる場合、そのテストケースは不合格です。

**さらなるバリデーションが必要となります:**

機密データを構成するものを判断することは状況によって異なるため、[逆アセンブルされた Objective-C と Swift のコードをレビューする (Reviewing Disassembled Objective-C and Swift Code)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0076.md) を使用して報告された各コード箇所を検査します。

* ペーストボードに書き込まれたデータが機密 (パスワード、トークン、個人データなど) であるかどうかを判断します。
