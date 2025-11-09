---
masvs_v1_id:
- MSTG-CODE-8
masvs_v2_id:
- MASVS-CODE-4
platform: android
title: メモリ破損バグ (Memory Corruption Bugs)
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
status: deprecated
covered_by: []
deprecation_note: 関連する弱点は開発プロセスの中で対処するのが最善です。詳細については [メモリ破損バグ (Memory Corruption Bugs)](../../../knowledge/android/MASVS-CODE/MASTG-KNOW-0005.md) を参照してください。
---

## 概要

## 静的解析

いろいろなアイテムを探してみます。

- ネイティブコードの部分はありますか。もしあれば、一般的なメモリ破損のセクションで与えられた問題をチェックします。ネイティブコードは JNI ラッパー、 .CPP/.H/.C ファイル、 NDK や他のネイティブフレームワークがあれば簡単に発見できます。
- Java コードや Kotlin コードはありますか。 [Android デシリアライゼーション脆弱性の簡単な歴史](https://securitylab.github.com/research/android-deserialization-vulnerabilities "android deserialization") で説明されているような、シリアライゼーション/デシリアライゼーション問題を探します。

Java/Kotlin コードでもメモリリークが発生する可能性があることに注意します。未登録ではない BroadcastReceivers 、 `Activity` または `View` クラスへの静的参照、 `Context` への参照をもつシングルトンクラス、内部クラス参照、匿名クラス参照、 AsyncTask 参照、ハンドラ参照、スレッディングの誤り、 TimerTask 参照などさまざまなアイテムを探します。詳細は以下で確認してください。

- [Android でメモリリークを回避する 9 つの方法](https://android.jlelse.eu/9-ways-to-avoid-memory-leaks-in-android-b6d81648e35e "9 ways to avoid memory leaks in Android")
- [Android のメモリリークパターン](https://android.jlelse.eu/memory-leak-patterns-in-android-4741a7fcb570 "Memory Leak Patterns in Android").

## 動的解析

実行にはいろいろな手順があります。

- ネイティブコードの場合、 Valgrind または Mempatrol を使用して、コードによるメモリ使用量とメモリ呼び出しを解析します。
- Java/Kotlin コードの場合、アプリを再コンパイルして [Squares leak canary](https://github.com/square/leakcanary "Leakcanary") を使用してみます。
- [Android Studio の Memory Profiler](https://developer.android.com/studio/profile/memory-profiler "Memory profiler") でリークがないか確認します。
- [Android Java Deserialization Vulnerability Tester](https://github.com/modzero/modjoda "Android Java Deserialization Vulnerability Tester") でシリアル化脆弱性がないか確認します。
