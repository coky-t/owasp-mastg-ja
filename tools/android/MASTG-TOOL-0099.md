---
title: FlowDroid
platform: android
source: https://github.com/secure-software-engineering/FlowDroid
---

FlowDroid は [soot](https://github.com/soot-oss/soot "soot") をベースとしたオープンソースツールであり、Java バイトコードをより簡単に解析および翻訳するためのフレームワークです。このツールは解析時に Android アプリのライフサイクル (`onCreate`、`onStart`、`onPause` など) とその UI コンポーネントのニュアンスを処理し、以下のような汚染解析を実行します。

- **コンテキスト依存 (Context-sensitive)**: 特定の実行コンテキストに基づいて、同じメソッドへの呼び出しを区別します。
- **オブジェクト依存 (Object-sensitive)**: 同じクラスであっても、個々のオブジェクトを識別します。
- **フロー依存 (Flow-sensitive)**: コード実行の順序を認識します。

FlowDroid は二つの方法で使用できます。クイック解析のためのスタンドアロンコマンドラインツールとして、あるいはより複雑な調査のためのライブラリとしてです。汚染解析の実行に加えて、FlowDroid は [このブログ投稿](https://medium.com/geekculture/generating-call-graphs-in-android-using-flowdroid-pointsto-analysis-7b2e296e6697 "Generating Call Graphs in Android Using FlowDroid + PointsTo Analysis by Navid Salehnamadi") で説明しているように、コールグラフを生成することもできます。
