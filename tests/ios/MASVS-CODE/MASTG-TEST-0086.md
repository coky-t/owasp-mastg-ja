---
masvs_v1_id:
- MSTG-CODE-8
masvs_v2_id:
- MASVS-CODE-4
platform: ios
title: メモリ破損バグ (Memory Corruption Bugs)
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## 概要

## 静的解析

ネイティブコードの部分はありますか。もしそうなら、一般的なメモリ破損のセクションで与えられた問題を確認します。ネイティブコードはコンパイル時に見つけることは少々困難です。ソースがある場合は C ファイルでは .c ソースファイルと .h ヘッダファイルを使用し、C++ では .cpp ファイルと .h ファイルを使用します。これは Swift および Objective-C の .swift および .m ソースファイルとは少し異なります。これらのファイルはソースの一部、またはサードパーティライブラリの一部であり、フレームワークとして登録され、Carthage, Swift Package Manager, Cocoapods などのさまざまなツールを介してインポートされます。

プロジェクト内のマネージコード (Objective-C / Swift) については、以下の項目を確認します。

- 二重解放の問題: `free` が与えられた領域に対して一度ではなく二度呼ばれるとき。
- 循環保持: メモリにマテリアルを保持するコンポーネント間の強い相互参照による循環依存関係を探します。
- `UnsafePointer` のインスタンスを使用することは間違って管理される可能性があり、さまざまなメモリ破損問題を可能にします。
- 手動で `Unmanaged` によるオブジェクトへの参照カウントを管理しようと、カウンタ番号の間違いや解放の遅すぎや早すぎにつながります。

[Realm アカデミーでこの話題について素晴らしい講演が行われました](https://academy.realm.io/posts/russ-bishop-unsafe-swift/ "Russh Bishop on Unsafe Swift") 。また、この話題について Ray Wenderlich は [実際に何が起こっているかを見るための素敵なチュートリアル](https://www.raywenderlich.com/780-unsafe-swift-using-pointers-and-interacting-with-c "Unsafe Swift: Using Pointers And Interacting With C") を提供しています。

> Swift 5 ではフルブロックの割り当て解除のみ可能であることに注意します。これはプレイグラウンドが少し変更されたことを意味しています。

## 動的解析

Xcode 8 で導入された Debug Memory Graph や Xcode の Allocations and Leaks instrument など、Xcode 内でメモリバグを特定するのに役立つさまざまなツールがあります。

次に、アプリケーションのテスト時に Xcode で `NSAutoreleaseFreedObjectCheckEnabled`, `NSZombieEnabled`, `NSDebugEnabled` を有効にすることで、メモリの解放が早すぎるか遅すぎるかを確認できます。

メモリ管理の面倒を見る手助けとなるさまざまなうまくまとめられた解説があります。これらは本章の参考情報リストにあります。
