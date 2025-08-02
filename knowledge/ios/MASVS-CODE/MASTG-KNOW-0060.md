---
masvs_category: MASVS-CODE
platform: ios
title: メモリ破損バグ (Memory Corruption Bugs)
---

iOS アプリケーションはさまざまな状況で [メモリ破損バグ](../../../Document/0x04h-Testing-Code-Quality.md#memory-corruption-bugs) に遭遇します。まず、一般的なメモリ破損バグのセクションで言及されているネイティブコードの問題があります。次に、Objective-C と Swift のいずれにも問題を引き起こす可能性のあるネイティブコードを実際にラップするさまざまな危険な操作があります。最後に、Swift と Objective-C の実装はいずれも使用されなくなったオブジェクトを保持するためにメモリリークが発生する可能性があります。

詳しくはこちら。

- <https://developer.ibm.com/tutorials/mo-ios-memory/>
- <https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/MemoryMgmt/Articles/MemoryMgmt.html>
- <https://medium.com/zendesk-engineering/ios-identifying-memory-leaks-using-the-xcode-memory-graph-debugger-e84f097b9d15>
