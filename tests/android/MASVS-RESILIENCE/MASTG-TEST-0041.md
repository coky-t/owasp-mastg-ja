---
masvs_v1_id:
- MSTG-CODE-4
masvs_v2_id:
- MASVS-RESILIENCE-3
platform: android
title: デバッグコードと詳細エラーログに関するテスト (Testing for Debugging Code and Verbose Error Logging)
masvs_v1_levels:
- R
profiles: [R]
status: deprecated
covered_by: [MASTG-TEST-0263]
deprecation_note: New version available in MASTG V2
---

## 概要

## 静的解析

[`StrictMode`](https://developer.android.com/reference/android/os/StrictMode) が有効かどうかを判断するには、`StrictMode.setThreadPolicy` または `StrictMode.setVmPolicy` メソッドを探します。ほとんどの場合、`onCreate` メソッドにあります。

スレッドポリシーの検出メソッドは以下のとおりです。

- `detectDiskWrites()`
- `detectDiskReads()`
- `detectNetwork()`

スレッドポリシー違反のペナルティは以下のとおりです。

- `penaltyLog()`: LogCat にメッセージをログ記録します。
- `penaltyDeath()`: 有効なすべてのペナルティの最後に実行して、アプリケーションをクラッシュします。
- `penaltyDialog()`: ダイアログを表示します。

StrictMode を使用するための [ベストプラクティス](https://code.tutsplus.com/tutorials/android-best-practices-strictmode--mobile-7581 "Android Best Practices: StrictMode") をご覧ください。

## 動的解析

`StrictMode` を検出するにはいくつかの方法があります。最善の選択はポリシーの役割の実装方法により異なります。以下があります。

- Logcat
- 警告ダイアログ
- アプリケーションクラッシュ
