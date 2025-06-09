---
platform: ios
title: 使用後にクリアされないペーストボードコンテンツ (Pasteboard Contents Not Cleared After Use)
id: MASTG-TEST-0278
type: [static]
weakness: MASWE-0053
threat: [app]
profiles: [L2]
---

## 概要

このテストは、アプリがバックグラウンドに移動したり終了する際に、一般的な [ペーストボード](../../../Document/0x06h-Testing-Platform-Interaction.md#pasteboard) のコンテンツをクリアするかどうかをチェックします。ペーストボードに機密データが残っていると、他のアプリからアクセスされ、データ漏洩につながる可能性があります。

アプリは `applicationDidEnterBackground:` や `applicationWillTerminate:` などの適切なライフサイクルメソッドで `UIPasteboard.general.items = []` を設定することで、一般的なペーストボードのコンテンツをクリアできます。

## 手順

1. [radare2 for iOS](../../../tools/ios/MASTG-TOOL-0073.md) を使用して静的解析スキャンを実行し、[`UIPasteboard.general`](https://developer.apple.com/documentation/uikit/uipasteboard/1622106-generalpasteboard "UIPasteboard generalPasteboard") プロパティの使用を検出します。
2. [radare2 for iOS](../../../tools/ios/MASTG-TOOL-0073.md) を使用して静的解析スキャンを実行し、[`UIPasteboard.setItems`](https://developer.apple.com/documentation/uikit/uipasteboard/setitems(_:options:) "UIPasteboard setItems") メソッドの使用を検出します。

## 結果

出力には関連する API が使用されている場所のリストを含む可能性があります。

## 評価

アプリが一般的なペーストボードを使用し、バックグラウンドに移動したり終了する際にそのコンテンツをクリアしていない場合、そのテストは不合格です。具体的には、適切なライフサイクルメソッドで、空の配列 (`[]`) を指定した `UIPasteboard.setItems` の呼び出しがあることを検証する必要があります。
