---
platform: ios
title: 期限切れにならないペーストボードコンテンツ (Pasteboard Contents Not Expiring)
id: MASTG-TEST-0279
type: [static]
weakness: MASWE-0053
threat: [app]
profiles: [L2]
---

## 概要

このテストは、アプリが `UIPasteboard.setItems(_:options:)` メソッドに `UIPasteboard.Options.expirationDate` オプションを使用して、一般的な [ペーストボード](../../../Document/0x06h-Testing-Platform-Interaction.md#pasteboard) のコンテンツに有効期限を設定しているかどうかをチェックします。機密データが有効期限なしでペーストボードに残されると、他のアプリから無期限にアクセスされ、データ漏洩につながる可能性があります。

## 手順

1. [radare2 for iOS](../../../tools/ios/MASTG-TOOL-0073.md) を使用して静的解析スキャンを実行し、[`UIPasteboard.general`](https://developer.apple.com/documentation/uikit/uipasteboard/1622106-generalpasteboard "UIPasteboard generalPasteboard") プロパティの使用を検出します。
2. [radare2 for iOS](../../../tools/ios/MASTG-TOOL-0073.md) を使用して静的解析スキャンを実行し、`UIPasteboard.setItems(_:options:)` メソッドの使用を検出します。

## 結果

出力には関連する API が使用されている場所のリストを含む可能性があります。

## 評価

アプリが一般的なペーストボードを使用し、そのコンテンツの有効期限を設定しない場合、そのテストは不合格です。具体的には、`UIPasteboard.setItems(_:options:)` メソッドが `UIPasteboard.Options.expirationDate` オプションを指定して呼び出されていることを確認します。
