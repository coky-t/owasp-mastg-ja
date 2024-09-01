---
title: hermes-dec
platform: generic
source: https://github.com/P1sec/hermes-dec/
---

[hermes-dec](https://github.com/P1sec/hermes-dec/) はコンパイルされた [hermes](https://reactnative.dev/docs/hermes) バイトコードをリバースエンジニアリングするためのツールであり、Android アプリと iOS アプリの両方に対応しています。[React Native](https://reactnative.dev/) で開発されたアプリでよく見られる [Hermes VM バイトコード (HBC)](https://lucasbaizer2.github.io/hasmer/hasm/instruction-docs/hbc86.html) 形式の逆コンパイルと逆アセンブルをサポートしています。

静的解析時に以下のファイルのいずれかに遭遇した場合、hermes-dec はファイルの内容の判別できるバージョンを復元する方法を提供します。

- index.android.bundle
- main.jsbundle

`file` を使用してタイプをチェックし、実際の Hermes バイトコードを扱っていることを確認します。

```bash
$ file main.jsbundle
main.jsbundle: Hermes JavaScript bytecode, version 90
```

代わりにプレーンテキストファイルであることが分かれば、あらゆるテキストエディタで開くことができ、hermes-dec は必要ありません。

```bash
$ file main.jsbundle
main.jsbundle: Unicode text, UTF-8 text
```

React Native モバイルアプリで静的解析を行っていて、[react-native-decompiler](https://github.com/numandev1/react-native-decompiler) が失敗するような状況で、hermes-dec を使用してみることができます。
