---
masvs_category: MASVS-CODE
platform: android
title: デバッグ可能アプリ (Debuggable Apps)
---

デバッグは開発者が Android アプリのエラーやバグを特定し修正するために不可欠なプロセスです。デバッガを使用することで、開発者はアプリをデバッグするデバイスを選択し、Java、Kotlin、C/C++ コードにブレークポイントを設定できます。これにより実行時に変数の解析や式の評価が可能になり、多くの問題の根本原因を特定できます。アプリをデバッグすることで、開発者はアプリの機能性とユーザー体験を向上させ、エラーやクラッシュがないスムーズな動作を確保できます。

デバッガを有効にしたすべてのプロセスでは JDWP プロトコルパケットを処理するための特別なスレッドを実行します。このスレッドは Android Manifest 内の [`Application` 要素](https://developer.android.com/guide/topics/manifest/application-element.html "Application element") に `android:debuggable="true"` 属性を持つアプリに対してのみ開始されます。
