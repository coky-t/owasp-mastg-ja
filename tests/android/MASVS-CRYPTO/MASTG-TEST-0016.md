---
masvs_v1_id:
- MSTG-CRYPTO-6
masvs_v2_id:
- MASVS-CRYPTO-1
platform: android
title: 乱数生成のテスト (Testing Random Number Generation)
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
status: deprecated
covered_by: ['MASTG-TEST-0204', 'MASTG-TEST-0205']
deprecation_reason: New version available in MASTG V2
---

## 概要

## 静的解析

乱数生成器のインスタンスをすべて特定して、カスタムクラスや既知のセキュアでないクラスを探します。例えば、`java.util.Random` は与えられた各シード値に対して同じ一連の数値を生成します。その結果、一連の数値は予測可能となります。代わりに、その分野の専門家により現時点で強力であると考えられている十分に検証されたアルゴリズムを選択し、適切な長さのシードを持つ十分にテストされた実装を使用すべきです。

デフォルトコンストラクタを使用して作成されていない `SecureRandom` のすべてのインスタンスを特定します。シード値を指定するとランダム性が低下する可能性があります。システム指定のシード値を使用して 128 バイト長の乱数を生成する [`SecureRandom` の引数なしコンストラクタ](https://wiki.sei.cmu.edu/confluence/display/java/MSC02-J.+Generate+strong+random+numbers "Generation of Strong Random Numbers") のみを使用します。

一般的に、PRNG が暗号的にセキュアであると宣言されていない場合 (`java.util.Random` など) 、それはおそらく統計的 PRNG であり、セキュリティ上機密であるコンテキストに使用すべきではありません。
擬似乱数生成器が既知であり、シードが推定できる場合、その生成器は [予測可能な数値を生成します](https://wiki.sei.cmu.edu/confluence/display/java/MSC63-J.+Ensure+that+SecureRandom+is+properly+seeded "Proper seeding of SecureRandom") 。128 ビットシードは「十分にランダムな」数値を生成するためのよい出発点です。

攻撃者はどのタイプの脆弱な疑似乱数生成器 (PRNG) が使用されているかを知ることで、[Java Random で行われたように](https://franklinta.com/2014/08/31/predicting-the-next-math-random-in-java/ "Predicting the next Math.random() in Java") 、以前に観測された値に基づいて次の乱数値を生成する概念実証を簡単に書くことができます。非常に脆弱なカスタム乱数生成器の場合にはパターンを統計的に観測することが可能かもしれません。推奨される方法はとにかく APK を逆コンパイルしてアルゴリズムを検査することです (静的解析を参照してください) 。

ランダム性をテストしたい場合には、数の大きなセットをキャプチャし Burp の [sequencer](https://portswigger.net/burp/documentation/desktop/tools/sequencer "Burp\'s Sequencer") で確認してランダム性の品質がどれほど良いかを確認します。

## 動的解析

上記のクラスやメソッドに [メソッドトレース (Method Tracing)](../../../techniques/android/MASTG-TECH-0033.md) を使用して、使用されている入出力値を判別できます。
