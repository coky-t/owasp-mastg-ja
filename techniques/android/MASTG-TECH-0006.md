---
title: インストール済みアプリの一覧 (Listing Installed Apps)
platform: android
---

デバイスにインストールされているアプリをターゲットにする場合、まず解析したいアプリケーションの正しいパッケージ名を把握する必要があります。インズトールされているアプリは、`pm` (Android Package Manager) を使用するか、`frida-ps` を使用することで取得できます。

```bash
$ adb shell pm list packages
package:sg.vantagepoint.helloworldjni
package:eu.chainfire.supersu
package:org.teamsik.apps.hackingchallenge.easy
package:org.teamsik.apps.hackingchallenge.hard
package:sg.vp.owasp_mobile.omtg_android
```

サードパーティアプリのみを表示するフラグ (`-3`) とその APK ファイルの場所 (`-f`) を含むことができ、後で `adb pull` 経由でダウンロードするときに使用できます。

```bash
$ adb shell pm list packages -3 -f
package:/data/app/sg.vantagepoint.helloworldjni-1/base.apk=sg.vantagepoint.helloworldjni
package:/data/app/eu.chainfire.supersu-1/base.apk=eu.chainfire.supersu
package:/data/app/org.teamsik.apps.hackingchallenge.easy-1/base.apk=org.teamsik.apps.hackingchallenge.easy
package:/data/app/org.teamsik.apps.hackingchallenge.hard-1/base.apk=org.teamsik.apps.hackingchallenge.hard
package:/data/app/sg.vp.owasp_mobile.omtg_android-kR0ovWl9eoU_yh0jPJ9caQ==/base.apk=sg.vp.owasp_mobile.omtg_android
```

これはアプリパッケージ ID で `adb shell pm path <app_package_id>` を実行するのと同じです。

```bash
$ adb shell pm path sg.vp.owasp_mobile.omtg_android
package:/data/app/sg.vp.owasp_mobile.omtg_android-kR0ovWl9eoU_yh0jPJ9caQ==/base.apk
```

`frida-ps -Uai` を使用して、接続されている USB デバイス (`-U`) に現在インストールされている (`-i`) すべてのアプリ (`-a`) を取得します。

```bash
$ frida-ps -Uai
  PID  Name                                      Identifier
-----  ----------------------------------------  ---------------------------------------
  766  Android System                            android
21228  Attack me if u can                        sg.vp.owasp_mobile.omtg_android
 4281  Termux                                    com.termux
    -  Uncrackable1                              sg.vantagepoint.uncrackable1
```

これは現在実行中のアプリの PID も表示することに注意します。"Identifier" と PID (ある場合) は後で必要になるため、書き留めておきます。
