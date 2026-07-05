---
platform: ios
title: 期限切れにならないペーストボードコンテンツ (Pasteboard Contents Not Expiring)
id: MASTG-TEST-0279
type: [static, code]
weakness: MASWE-0053
threat: [app]
profiles: [L2]
knowledge: [MASTG-KNOW-0083]
---

## 概要

このテストは、アプリが [`UIPasteboard.setItems(_:options:)`](https://developer.apple.com/documentation/uikit/uipasteboard/setitems(_:options:) "UIPasteboard setItems(_:options:)") メソッドに `UIPasteboard.Options.expirationDate` オプションを使用して、汎用ペーストボード ([`UIPasteboard.general`](https://developer.apple.com/documentation/uikit/uipasteboard/general "UIPasteboard generalPasteboard")) のコンテンツに有効期限を設定しているかどうかをチェックします。機密データが有効期限なしでペーストボードに残されると、他のアプリから無期限にアクセスされ、データ漏洩につながる可能性があります。汎用ペーストボードの詳細については [ペーストボード (Pasteboard)](../../../knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0083.md) を参照してください。

## 手順

1. [アプリパッケージの探索 (Exploring the App Package)](../../../techniques/ios/MASTG-TECH-0058.md) を使用して、アプリパッケージから関連するバイナリを抽出します。
2. [iOS での静的解析 (Static Analysis on iOS)](../../../techniques/ios/MASTG-TECH-0066.md) を使用して、アプリバイナリ内の関連する API を探します。

## 結果

出力には関連する API が使用されている場所のリストを含む可能性があります。

## 評価

アプリが汎用ペーストボードを使用し、そのコンテンツの有効期限を設定しない場合、そのテストケースは不合格です。具体的には、`UIPasteboard.setItems(_:options:)` メソッドが `UIPasteboard.Options.expirationDate` オプションを指定して呼び出されていることを確認します。
