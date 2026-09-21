---
title: 暗黙的インテントとブロードキャストの傍受 (Sniffing Implicit Intents and Broadcasts)
platform: android
---

アプリが受信者を制限することなく (たとえば、明示的なターゲットパッケージや必須のパーミッションなしで) 暗黙的インテントやブロードキャストを送信する場合、デバイス上のあらゆるアプリがそれを受信するように登録できます。この技法を使用して、そのようなインテントやブロードキャストを観察し、それらが伝えるデータを調査できます。暗黙的インテントについては [暗黙的インテント (Implicit Intents)](../../knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0025.md) を、ブロードキャストについては [Android ブロードキャストレシーバ (Android Broadcast Receivers)](../../knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0134.md) を参照してください。

## [adb](../../tools/android/MASTG-TOOL-0004.md) を使用する

アクティビティマネージャサービスで、特定のアクションに対する直近のブロードキャストを観察できます。これが表示するのはインテントのメタデータであり、エクストラの内容ではないことに注意してください。

```bash
adb shell dumpsys activity broadcasts | grep <action>
```

エクストラをを捕捉するには、そのアクションに対するレシーバを登録し、それが受信したインテントをログ記録します。小さな専用アプリまたは以下の計装ツールでこれを行うことができます。

## [Drozer](../../tools/android/MASTG-TOOL-0015.md) を使用する

drozer は、特定のアクションに一致するブロードキャストを傍受するレシーバを登録し、エクストラを含むインテント全体を出力できます。

```bash
run app.broadcast.sniff --action <action>
```

エクストラに機密データを伝えるブロードキャストの出力例:

```text
Action: <action>
Raw: Intent { act=<action> flg=0x10 (has extras) }
Extra: <key>=<value> (java.lang.String)
```

## メソッドフックを使用する

[メソッドフック (Method Hooking)](MASTG-TECH-0043.md) で説明されているように、関連する API (たとえば、`Context.sendBroadcast`, `Context.startActivity`, `BroadcastReceiver.onReceive`) をフックすることで、インテントが送信または受信される時点で観察することも可能です。これはターゲットアプリのプロセス内からインテントオブジェクトを捕捉し、受信者や必須パーミッションにより外部レシーバが観測することを防ぐ場合に役立ちます。
