---
masvs_v1_id:
- MSTG-PLATFORM-4
masvs_v2_id:
- MASVS-PLATFORM-1
platform: ios
title: UIPasteboard のテスト (Testing UIPasteboard)
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
status: deprecated
deprecation_note: New version available in MASTG V2
covered_by: [MASTG-TEST-0276, MASTG-TEST-0277, MASTG-TEST-0278, MASTG-TEST-0279, MASTG-TEST-0280]
---

## 概要

## 静的解析

**システム全体の汎用ペーストボード** は [`generalPasteboard`](https://developer.apple.com/documentation/uikit/uipasteboard/1622106-generalpasteboard?language=objc "UIPasteboard generalPasteboard") を使用して取得できます。このメソッドについてソースコードやコンパイル済みバイナリを検索します。機密データを扱う場合、システム全体の汎用ペーストボードの使用は避けるべきです。

**カスタムペーストボード** は [`pasteboardWithName:create:`](https://developer.apple.com/documentation/uikit/uipasteboard/1622074-pasteboardwithname?language=objc "UIPasteboard pasteboardWithName:create:") または [`pasteboardWithUniqueName`](https://developer.apple.com/documentation/uikit/uipasteboard/1622087-pasteboardwithuniquename?language=objc "UIPasteboard pasteboardWithUniqueName") で作成できます。カスタムペーストボードが永続的に設定されているかどうかを検証します。これは iOS 10 以降非推奨であるためです。代わりに共有コンテナを使用する必要があります。

さらに、以下を検査できます。

- ペーストボードが [`removePasteboardWithName:`](https://developer.apple.com/documentation/uikit/uipasteboard/1622072-removepasteboardwithname?language=objc "UIPasteboard removePasteboardWithName:") で削除されているかどうかをチェックします。これはアプリのペーストボードを無効にし、それで使用されているすべてのリソースを解放します (汎用ペーストボードには影響しません)。
- 除外されているペーストボードがあるかどうかをチェックします。`UIPasteboardOptionLocalOnly` オプションを指定して `setItems:options:` を呼び出す必要があります。
- 期限切れのペーストボードがあるかどうかをチェックします。`UIPasteboardOptionExpirationDate` オプションを指定して `setItems:options:` を呼び出す必要があります。
- バックグラウンドに移行するとき、または終了するときに、アプリがペーストボードアイテムをクリアしているかどうかをチェックします。これは機密データ露出を制限しようとする一部のパスワードマネージャアプリによって行われます。

## 動的解析

### ペーストボードの使用を検出する

以下をフックまたはトレースします。

- システム全体の汎用ペーストボードには `generalPasteboard`
- カスタムペーストボードには `pasteboardWithName:create:` および `pasteboardWithUniqueName`

### ペーストボードの永続的な使用を検出する

非推奨の [`setPersistent:`](https://developer.apple.com/documentation/uikit/uipasteboard/1622096-setpersistent?language=objc "UIPasteboard setPersistent:") メソッドをフックまたはトレースし、それが呼び出されているかどうかを検証します。

### ペーストボードアイテムの監視と検査

実行時にペーストボードアイテムを監視および検査するには、[ペーストボードの監視 (Monitoring the Pasteboard)](../../../techniques/ios/MASTG-TECH-0134.md) の手順に従います。
