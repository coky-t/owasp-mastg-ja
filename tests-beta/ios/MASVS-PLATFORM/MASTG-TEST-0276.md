---
platform: ios
title: iOS の汎用ペーストボードの使用 (Use of the iOS General Pasteboard)
id: MASTG-TEST-0276
type: [static]
weakness: MASWE-0053
threat: [app]
prerequisites:
- identify-sensitive-data
profiles: [L2]
knowledge: [MASTG-KNOW-0083]
---

## 概要

このテストはアプリがシステム全体で汎用 [ペーストボード](../../../Document/0x06h-Testing-Platform-Interaction.md#pasteboard) を使用しているかどうかをチェックします。これはデバイスの再起動やアプリのアンインストール後も永続的に保持され、すべてのフォアグラウンドアプリや、場合によっては他のデバイスからもアクセスできます。ここに機密データを置くと、プライバシーリスクを引き起こすかもしれません。

このテストは汎用ペーストボード ([`UIPasteboard.general`](https://developer.apple.com/documentation/uikit/uipasteboard/general)) を使用するコードを静的に解析し、機密データが以下のメソッドのいずれかを使用して書き込まれているかどうかをチェックします。

- [`addItems`](https://developer.apple.com/documentation/uikit/uipasteboard/additems(_:))
- [`setItems`](https://developer.apple.com/documentation/uikit/uipasteboard/setitems(_:options:))
- [`setData`](https://developer.apple.com/documentation/uikit/uipasteboard/setdata(_:forpasteboardtype:))
- [`setValue`](https://developer.apple.com/documentation/uikit/uipasteboard/setvalue(_:forpasteboardtype:))

## 手順

1. [radare2 (iOS)](../../../tools/ios/MASTG-TOOL-0073.md) を使用して静的解析を実行し、汎用ペーストボードの使用を検出します。
2. [radare2 (iOS)](../../../tools/ios/MASTG-TOOL-0073.md) を使用して静的解析を実行し、機密データを取り扱う可能性のあるペーストボードメソッドの使用を検出します。

## 結果

出力には関連する API が使用されている場所のリストを含む可能性があります。

## 評価

`UIPasteboard.generalPasteboard` への呼び出しが行われ、機密データがそこに書き込まれる場合、そのテストは不合格です。

機密データを構成するものの判断はコンテキストに依存するため、静的に検出することは困難なことがあります。前述の方法を使用して機密データがペーストボードに書き込まれているかどうかをチェックするには、リバースエンジニアされたコードで報告されたコード位置を検査します ([逆アセンブルされた Objective-C と Swift のコードをレビューする (Reviewing Disassembled Objective-C and Swift Code)](../../../techniques/ios/MASTG-TECH-0076.md) を参照)。
