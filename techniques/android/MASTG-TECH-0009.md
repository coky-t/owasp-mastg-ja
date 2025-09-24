---
title: システムログの監視 (Monitoring System Logs)
platform: android
---

Android では、[`Logcat`](https://developer.android.com/tools/debugging/debugging-log.html "Debugging with Logcat") を使用することで、システムメッセージのログを簡単に調査できます。Logcat を実行するには二つの方法があります。

- Logcat は Android Studio の _Dalvik Debug Monitor Server_ (DDMS) の一部です。アプリがデバッグモードで実行されている場合、ログ出力は Android Monitor の Logcat タブに表示されます。Logcat でパターンを定義することで、アプリのログ出力をフィルタできます。

<img src="../../Document/Images/Chapters/0x05b/log_output_Android_Studio.png" width="100%" />

- [adb](../../tools/android/MASTG-TOOL-0004.md) で Logcat を実行すると、ログ出力を永続的に保存できます。

```bash
adb logcat > logcat.log
```

以下のコマンドで、パッケージ名を入れるだけで、スコープ内のアプリのログ出力を具体的に grep できます。もちろん、`ps` で PID を取得するには、アプリが実行されている必要があります。

```bash
adb logcat | grep "$(adb shell ps | grep <package-name> | awk '{print $2}')"
```

アプリの PID をすでに分かっている場合には、`--pid` フラグを使用して直接指定できます。

また、ログに特定の文字列やパターンがでてくることが予想される場合、さらにフィルタや正規表現 (たとえば `logcat` の正規表現フラグ `-e <expr>, --regex=<expr>` を使用) を適用することもできます。
