---
title: gplaycli
platform: android
source: https://github.com/matlink/gplaycli
---

[gplaycli](https://github.com/matlink/gplaycli "gplaycli") は Google Play Store から Android アプリケーションを検索、インストール、アップデートするための Python ベースの CLI ツールです。[インストール手順](https://github.com/matlink/gplaycli#installation "gplaycli Installation") に従えば、実行できるようになります。gplaycli にはいくつかのオプションがあります。詳細についてはヘルプ (`-h`) を参照してください。

アプリのパッケージ名 (または AppID) が不明な場合は、キーワードベースで APK の検索 (`-s`) を実行できます。

```bash
$ gplaycli -s "google keep"

Title                          Creator     Size      Last Update  AppID                                    Version

Google Keep - notes and lists  Google LLC  15.78MB   4 Sep 2019   com.google.android.keep                  193510330
Maps - Navigate & Explore      Google LLC  35.25MB   16 May 2019  com.google.android.apps.maps             1016200134
Google                         Google LLC  82.57MB   30 Aug 2019  com.google.android.googlequicksearchbox  301008048
```

> [!NOTE]
> gplaycli を使用する際、地域 (Google Play) の制限が適用されます。お住まいの国で制限されているアプリにアクセスするには、[アプリの入手と抽出](../../techniques/android/MASTG-TECH-0003.md) で説明しているような代替アプリストアを使用してください。
