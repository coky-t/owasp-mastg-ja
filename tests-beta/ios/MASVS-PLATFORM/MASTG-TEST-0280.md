---
platform: ios
title: ローカルデバイスに制限されていないペーストボードコンテンツ (Pasteboard Contents Not Restricted to Local Device)
id: MASTG-TEST-0280
type: [static]
weakness: MASWE-0053
threat: [app]
profiles: [L2]
---

## 概要

このテストは、アプリが `UIPasteboard.setItems(_:options:)` メソッドに `UIPasteboard.OptionsKey.localOnly` オプションを使用して、一般的な [ペーストボード](../../../Document/0x06h-Testing-Platform-Interaction.md/#pasteboard) のコンテンツをローカルデバイスに制限しているかどうかをチェックします。この制限なしに機密データが一般的なペーストボードに配置されると、ユニバーサルクリップボードを介してデバイス間で同期され、データ漏洩につながる可能性があります。

## 手順

1. [radare2 for iOS](../../../tools/ios/MASTG-TOOL-0073.md) を使用して静的解析スキャンを実行し、[`UIPasteboard.general`](https://developer.apple.com/documentation/uikit/uipasteboard/1622106-generalpasteboard "UIPasteboard generalPasteboard") プロパティの使用を検出します。
2. [radare2 for iOS](../../../tools/ios/MASTG-TOOL-0073.md) を使用して静的解析スキャンを実行し、`UIPasteboard.setItems(_:options:)` メソッドの使用を検出します。

## 結果

出力には関連する API が使用されている場所のリストを含む可能性があります。

## 評価

アプリが一般的なペーストボードを使用し、そのコンテンツをローカルデバイスに制限しない場合、そのテストは不合格です。具体的には、`UIPasteboard.setItems(_:options:)` メソッドが `UIPasteboard.Options.localOnly` オプションを指定して呼び出されていることを確認します。
