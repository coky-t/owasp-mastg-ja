---
masvs_v1_id:
- MSTG-CODE-4
masvs_v2_id:
- MASVS-RESILIENCE-3
platform: android
title: デバッグコードと詳細エラーログに関するテスト (Testing for Debugging Code and Verbose Error Logging)
masvs_v1_levels:
- R
---

## 概要

## 静的解析

`StrictMode` が有効かどうかを判断するには、`StrictMode.setThreadPolicy` または `StrictMode.setVmPolicy` メソッドを探します。ほとんどの場合、`onCreate` メソッドにあります。

[スレッドポリシーの検出方法](https://javabeat.net/strictmode-android-1/ "What is StrictMode in Android?") は以下のとおりです。

```java
detectDiskWrites()
detectDiskReads()
detectNetwork()
```

[スレッドポリシー違反のペナルティ](https://javabeat.net/strictmode-android-1/ "What is StrictMode in Android?") は以下のとおりです。

```java
penaltyLog() // Logs a message to LogCat
penaltyDeath() // Crashes application, runs at the end of all enabled penalties
penaltyDialog() // Shows a dialog
```

StrictMode を使用するための [ベストプラクティス](https://code.tutsplus.com/tutorials/android-best-practices-strictmode--mobile-7581 "Android Best Practices: StrictMode") をご覧ください。

## 動的解析

`StrictMode` を検出するにはいくつかの方法があります。最善の選択はポリシーの役割の実装方法により異なります。以下があります。

- Logcat
- 警告ダイアログ
- アプリケーションクラッシュ
