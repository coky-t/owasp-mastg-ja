---
masvs_v1_id:
- MSTG-CODE-2
masvs_v2_id:
- MASVS-RESILIENCE-4
platform: android
title: アプリがデバッグ可能であるかのテスト (Testing whether the App is Debuggable)
masvs_v1_levels:
- R
status: deprecated
covered_by: [MASTG-TEST-0226,MASTG-TEST-0227]
deprecation_note: New version available in MASTG V2
---

## 概要

## 静的解析

`AndroidManifest.xml` をチェックして `android:debuggable` 属性が設定されているかどうかを判断し、その属性の値を見つけます。

```xml
    ...
    <application android:allowBackup="true" android:debuggable="true" android:icon="@drawable/ic_launcher" android:label="@string/app_name" android:theme="@style/AppTheme">
    ...
```

以下のコマンドラインで Android SDK の `aapt` ツールを使用すると、`android:debuggable="true"` ディレクティブが存在するかどうかをすばやく確認できます。

```bash
# If the command print 1 then the directive is present
# The regex search for this line: android:debuggable(0x0101000f)=(type 0x12)0xffffffff
$ aapt d xmltree sieve.apk AndroidManifest.xml | grep -Ec "android:debuggable\(0x[0-9a-f]+\)=\(type\s0x[0-9a-f]+\)0xffffffff"
1
```

リリースビルドの場合、この属性は常に `"false"` (デフォルト値) に設定すべきです。

## 動的解析

`adb` を使用して、アプリケーションがデバッグ可能かどうかを判断できます。

以下のコマンドを使用します。

```bash
# If the command print a number superior to zero then the application have the debug flag
# The regex search for these lines:
# flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
# pkgFlags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
$ adb shell dumpsys package com.mwr.example.sieve | grep -c "DEBUGGABLE"
2
$ adb shell dumpsys package com.nondebuggableapp | grep -c "DEBUGGABLE"
0
```

アプリケーションがデバッグ可能である場合、アプリケーションコマンドを実行することは簡単です。`adb` シェルで、バイナリ名にパッケージ名とアプリケーションコマンドを追加して `run-as` を実行します。

```bash
$ run-as com.vulnerable.app id
uid=10084(u0_a84) gid=10084(u0_a84) groups=10083(u0_a83),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats) context=u:r:untrusted_app:s0:c512,c768
```

[Android Studio](https://developer.android.com/tools/debugging/debugging-studio.html "Debugging with Android Studio") を使用して、アプリケーションをデバッグし、アプリのデバッグアクティベーションを検証することもできます。

アプリケーションがデバッグ可能かどうかを判断する別の方法は、実行中のプロセスに `jdb` をアタッチすることです。これが成功する場合、デバッグが有効になります。

以下の手順を使用して `jdb` でデバッグセッションを開始できます。

1. `adb` と `jdwp` を使用して、デバッグしたいアクティブなアプリケーションの PID を特定します。

    ```bash
    $ adb jdwp
    2355
    16346  <== last launched, corresponds to our application
    ```

2. `adb` を使用してアプリケーションプロセス (PIDを使用) とホストコンピュータの間に特定のローカルポートを使用した通信チャネルを作成します。

    ```bash
    # adb forward tcp:[LOCAL_PORT] jdwp:[APPLICATION_PID]
    $ adb forward tcp:55555 jdwp:16346
    ```

3. `jdb` を使用して、デバッガをローカル通信チャネルポートにアタッチし、デバッグセッションを開始します。

    ```bash
    $ jdb -connect com.sun.jdi.SocketAttach:hostname=localhost,port=55555
    Set uncaught java.lang.Throwable
    Set deferred uncaught java.lang.Throwable
    Initializing jdb ...
    > help
    ```

デバッグに関するいくつかの注釈:

- [jadx](../../../tools/android/MASTG-TOOL-0018.md) を使用してブレークポイント挿入のための重要な場所を特定できます。
- jdb についての基本的なコマンドの使用方法は [Tutorialspoint](https://www.tutorialspoint.com/jdb/jdb_basic_commands.htm "jdb basic commands") にあります。
- `jdb` がローカル通信チャネルポートにバインドされている際に "the connection to the debugger has been closed" (デバッガへの接続が閉じられた) というエラーが表示された場合、すべての adb セッションを終了し、新しい一つのセッションを開始します。
