--- 
title: アプリパーミッションの取得 (Obtaining App Permissions)
platform: android 
---

Android パーミッションは `AndroidManifest.xml` ファイル内の `<uses-permission>` タグを使用して宣言されます。それらを表示するには複数のツールを使用できます。

## AndroidManifest の使用

[AndroidManifest から情報の取得 (Obtaining Information from the AndroidManifest)](MASTG-TECH-0117.md) の説明に従って `AndroidManifest.xml` を抽出し、すべての [`<uses-permission>`](https://developer.android.com/guide/topics/manifest/uses-permission-element) 要素を取得します。

## [aapt2](../../tools/android/MASTG-TOOL-0124.md) の使用

`aapt` を使用して、アプリケーションが要求するパーミッションを表示できます。

```bash
$ aapt d permissions org.owasp.mastestapp.apk
package: org.owasp.mastestapp
uses-permission: name='android.permission.INTERNET'
uses-permission: name='android.permission.CAMERA'
uses-permission: name='android.permission.WRITE_EXTERNAL_STORAGE'
uses-permission: name='android.permission.READ_CONTACTS'
uses-permission: name='android.permission.READ_EXTERNAL_STORAGE'
uses-permission: name='org.owasp.mastestapp.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION'
```

## [ADB](../../tools/android/MASTG-TOOL-0004.md) の使用

`adb` を使用して、アプリケーションが要求するパーミッションを表示できます。また、実行時のパーミッションの状態 (許可または拒否) も表示します。

```bash
$ adb shell dumpsys package org.owasp.mastestapp | grep permission
    declared permissions:
    requested permissions:
      android.permission.INTERNET
      android.permission.CAMERA
      android.permission.WRITE_EXTERNAL_STORAGE
      android.permission.READ_CONTACTS
      android.permission.READ_EXTERNAL_STORAGE
    install permissions:
      android.permission.INTERNET: granted=true
      runtime permissions:
        android.permission.READ_EXTERNAL_STORAGE: granted=false, flags=[ RESTRICTION_INSTALLER_EXEMPT]
        android.permission.CAMERA: granted=false
        android.permission.WRITE_EXTERNAL_STORAGE: granted=false, flags=[ RESTRICTION_INSTALLER_EXEMPT]
        android.permission.READ_CONTACTS: granted=false
```
