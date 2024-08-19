---
title: Android SDK
platform: android
---

ローカル Android SDK のインストールは Android Studio を介して管理されます。Android Studio で空のプロジェクトを作成し、**Tools** -> **SDK Manager** を選択して SDK Manager GUI を開きます。**SDK Platforms** タブで複数の API レベルの SDK をインストールします。最近の API レベルは以下のとおりです。

- Android 11.0 (API レベル 30)
- Android 10.0 (API レベル 29)
- Android 9.0 (API レベル 28)
- Android 8.1 (API レベル 27)
- Android 8.0 (API レベル 26)

すべての Android コードネーム、そのバージョン番号、API レベルの概要は [Android 開発者向けドキュメント](https://source.android.com/setup/start/build-numbers "Codenames, Tags, and Build Numbers") にあります。

<img src="../../Document/Images/Chapters/0x05c/sdk_manager.jpg" width="100%" />

インストールされた SDK は以下のパスにあります。

Windows:

```bash
C:\Users\<username>\AppData\Local\Android\sdk
```

MacOS:

```bash
/Users/<username>/Library/Android/sdk
```

注: Linux では、SDK ディレクトリを選択する必要があります。`/opt`, `/srv`, `/usr/local` が一般的な選択肢です。
