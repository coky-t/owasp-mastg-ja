---
title: 相互参照の取得 (Retrieving Cross References)
platform: android
---

## Java および Kotlin

Java 相互参照の取得をサポートする RE ツールは多くあります。GUI ベースのツールの多くでは、通常、目的の関数を右クリックして対応するオプション (Ghidra の **Show References to** や [jadx](../../tools/android/MASTG-TOOL-0018.md) の [**Find Usage**](https://github.com/skylot/jadx/wiki/jadx-gui-features-overview#find-usage "jadx - find-usage") など) を選択することでこれを実行します。

## ネイティブコード

Java 解析と同様に、Ghidra を使用してネイティブライブラリを解析し、目的の関数を右クリックして **Show References to** を選択することで相互参照を取得できます。
