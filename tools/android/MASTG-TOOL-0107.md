---
title: jnitrace
platform: android
source: https://github.com/chame1eon/jnitrace
hosts: [windows, linux, macOS]
---

jnitrace は Android アプリでの JNI API の使用をトレースするための Frida ベースのツールです。

Android アプリに含まれるネイティブライブラリは Android ランタイムを利用するために JNI API を使用することがよくあります。手作業によるリバースエンジニアリングでこれらの呼び出しを追跡するのは、時間がかかり面倒な作業になるかもしれません。jnitrace は frida-trace や strace に似た動的解析トレースツールとして機能しますが、JNI 用です。

<img src="https://i.ibb.co/ZJ04cBB/jnitrace-1.png" style="width: 80%; border-radius: 5px; margin: 2em" />
