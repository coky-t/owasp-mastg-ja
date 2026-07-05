---
platform: ios
title: >-
  ローカルデバイスに制限されていないペーストボードコンテンツ (Pasteboard Contents Not Restricted to Local
  Device)
id: MASTG-TEST-0280
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

# MASTG-TEST-0280 ローカルデバイスに制限されていないペーストボードコンテンツ (Pasteboard Contents Not Restricted to Local Device)

### 概要

このテストは、アプリが [`UIPasteboard.setItems(_:options:)`](https://developer.apple.com/documentation/uikit/uipasteboard/setitems\(_:options:\)) メソッドに `UIPasteboard.OptionsKey.localOnly` オプションを使用して、汎用ペーストボード ([`UIPasteboard.general`](https://developer.apple.com/documentation/uikit/uipasteboard/general)) のコンテンツをローカルデバイスに制限しているかどうかをチェックします。この制限なしに機密データが汎用ペーストボードに配置されると、ユニバーサルクリップボードを介してデバイス間で同期され、データ漏洩につながる可能性があります。汎用ペーストボードの詳細については [ペーストボード (Pasteboard)](https://github.com/coky-t/owasp-mastg-ja/blob/master/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0083.md) を参照してください。

### 手順

1. [アプリパッケージの探索 (Exploring the App Package)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0058.md) を使用して、アプリパッケージから関連するバイナリを抽出します。
2. [iOS での静的解析 (Static Analysis on iOS)](../../../techniques/ios/MASTG-TECH-0066.md) を使用して、アプリバイナリ内の関連する API を探します。

### 結果

出力には関連する API が使用されている場所のリストを含む可能性があります。

### 評価

アプリが汎用ペーストボードを使用し、そのコンテンツをローカルデバイスに制限しない場合、そのテストケースは不合格です。具体的には、`UIPasteboard.setItems(_:options:)` メソッドが `UIPasteboard.Options.localOnly` オプションを指定して呼び出されていることを確認します。
