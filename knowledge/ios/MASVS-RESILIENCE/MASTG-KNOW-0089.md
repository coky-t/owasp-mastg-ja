---
masvs_category: MASVS-RESILIENCE
platform: ios
title: 難読化 (Obfuscation)
---

["モバイルアプリの改竄とリバースエンジニアリング"](../../../Document/0x04c-Tampering-and-Reverse-Engineering.md#obfuscation) の章では一般的にモバイルアプリで使用できるよく知られた難読化技法をいくつか紹介しています。

## 名前の難読化

標準コンパイラはソースコードのクラス名と関数名に基づいてバイナリシンボルを生成します。したがって、難読化が適用されない場合には、シンボル名は意味を持ち、アプリバイナリから直接簡単に読み取ることができます。例えば、脱獄を検出する関数は関連するキーワード ("jailbreak" など) を検索することで見つけることができます。以下のリストは [DVIA-v2](../../../apps/ios/MASTG-APP-0024.md) から逆アセンブルされた関数 `JailbreakDetectionViewController.jailbreakTest4Tapped` を示しています。

```assembly
__T07DVIA_v232JailbreakDetectionViewControllerC20jailbreakTest4TappedyypF:
stp        x22, x21, [sp, #-0x30]!
mov        rbp, rsp
```

難読化後は以下のリストに示すようにシンボルの名前が意味をなさなくなったことがわかります。

```assembly
__T07DVIA_v232zNNtWKQptikYUBNBgfFVMjSkvRdhhnbyyFySbyypF:
stp        x22, x21, [sp, #-0x30]!
mov        rbp, rsp
```

とはいえ、これは関数、クラス、フィールドの名前にのみ適用されます。実際のコードは変更されないままであるため、攻撃者は逆アセンブルされたバージョンの関数を読み取り、(たとえば、セキュリティアルゴリズムのロジックを取得するために) その目的を理解しようとすることができます。

## 命令の差し替え

この技法は加算や減算などの標準的な二項演算子をより複雑な表現に置き換えます。例えば、加算 `x = a + b` は `x = -(-a) - (-b)` として表すことができます。ただし、同じ置換表現を使用することで簡単に元に戻すことができるため、単一のケースに複数の差し替え技法を追加して、ランダム因子を導入することをお勧めします。この技法は難読化解除に対して脆弱ですが、差し替えの複雑さと深さによっては適用に時間がかかることがあります。

## 制御フローの平坦化

制御フローの平坦化は元のコードをより複雑な表現に置き換えます。この変換は関数の本体を基本ブロックに分割し、プログラムフローを制御する switch ステートメントを使用して、それらすべてを単一の無限ループ内に配置します。これにより、通常はコードが読みやすくなる自然な条件構造が削除されるため、プログラムフローをたどることが著しく困難になります。

<img src="../../../Document/Images/Chapters/0x06j/control-flow-flattening.png" width="600px">

この画像は制御フローの平坦化がコードをどのように変更するかを示しています。詳細については ["制御フローの平坦化による C++ プログラムの難読化"](https://web.archive.org/web/20240414202600/http://ac.inf.elte.hu/Vol_030_2009/003.pdf) を参照してください。

## デッドコードインジェクション

この技法ではデッドコードをプログラムに挿入することにより、プログラムの制御フローがより複雑になります。デッドコードは元のプログラムの動作に影響を与えないコードのスタブですが、リバースエンジニアリングプロセスに対するオーバーヘッドを増加させます。

## 文字列の暗号化

アプリケーションはハードコードされた鍵、ライセンス、トークン、エンドポイント URL とともにコンパイルされることがよくあります。デフォルトでは、これらはすべて、アプリケーションのバイナリのデータセクションにプレーンテキストで保存されます。この技法はこれらの値を暗号化し、プログラムにより使用される前にデータを復号化するコードのスタブをプログラムに挿入します。

## 推奨ツール

- [SwiftShield](../../../tools/ios/MASTG-TOOL-0068.md) を使用して名前の難読化を実行できます。 Xcode プロジェクトのソースコードを読み取り、コンパイラが使用される前にクラス、メソッド、フィールドのすべての名前をランダムな値に置き換えます。
- [obfuscator-llvm](https://github.com/obfuscator-llvm) は中間表現 (Intermediate Representation, IR) で動作します。シンボルの難読化、文字列の暗号化、制御フローの平坦化に使用できます。 IR をベースとしているため、 SwiftShield と比較してアプリケーションの情報を大幅に隠すことができます。

iOS の難読化技法については記事 ["Protecting Million-User iOS Apps with Obfuscation: Motivations, Pitfalls, and Experience"](https://faculty.ist.psu.edu/wu/papers/obf-ii.pdf "Paper - Protecting Million-User iOS Apps with Obfuscation: Motivations, Pitfalls, and Experience") をご覧ください。
