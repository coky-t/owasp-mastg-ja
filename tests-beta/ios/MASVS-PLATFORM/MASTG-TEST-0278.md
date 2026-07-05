---
platform: ios
title: 使用後にクリアされないペーストボードコンテンツ (Pasteboard Contents Not Cleared After Use)
id: MASTG-TEST-0278
type:
  - static
  - code
weakness: MASWE-0053
threat:
  - app
profiles:
  - L2
knowledge:
  - MASTG-KNOW-0083
---

# MASTG-TEST-0278 使用後にクリアされないペーストボードコンテンツ (Pasteboard Contents Not Cleared After Use)

### 概要

このテストは、アプリがバックグラウンドに移動したり終了する際に、汎用 [ペーストボード (Pasteboard)](https://github.com/coky-t/owasp-mastg-ja/blob/master/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0083.md) のコンテンツをクリアするかどうかをチェックします。ペーストボードに機密データが残っていると、他のアプリからアクセスされ、データ漏洩につながる可能性があります。

アプリは `applicationDidEnterBackground:` や `applicationWillTerminate:` などの適切なライフサイクルメソッドで `UIPasteboard.general.items = []` を設定することで、汎用ペーストボードのコンテンツをクリアできます。これはリバースエンジニアされたコードでは [`UIPasteboard.general`](https://developer.apple.com/documentation/uikit/uipasteboard/1622106-generalpasteboard) および [`UIPasteboard.setItems`](https://developer.apple.com/documentation/uikit/uipasteboard/setitems\(_:options:\)) を空の配列 (`[]`) で呼び出すことに相当します。

### 手順

1. [アプリパッケージの探索 (Exploring the App Package)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0058.md) を使用して、アプリパッケージから関連するバイナリを抽出します。
2. [iOS での静的解析 (Static Analysis on iOS)](../../../techniques/ios/MASTG-TECH-0066.md) を使用して、アプリバイナリ内の関連する API を探します。

### 結果

出力には関連する API が使用されている場所のリストを含む可能性があります。

### 評価

アプリが汎用ペーストボードを使用し、バックグラウンドに移動したり終了する際にそのコンテンツをクリアしていない場合、そのテストケースは不合格です。具体的には、適切なライフサイクルメソッドで、空の配列 (`[]`) を指定した `UIPasteboard.setItems` の呼び出しがあることを検証する必要があります。
