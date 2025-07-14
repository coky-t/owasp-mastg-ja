---
title: 非ルート化デバイスでの動的解析 (Dynamic Analysis on Non-Rooted Devices)
platform: android
---

非ルート化デバイスにはアプリケーションの実行対象となる環境を複製できるという利点があります。

[objection](../../tools/generic/MASTG-TOOL-0038.md) などのツールのおかげで、ルート化されたデバイスにいるかのようにアプリをテストするためにアプリにパッチを適用できます (もちろんそのアプリ一つに投獄されていますが)。そのためにはもう一つの手順を実行する必要があります。[APK にパッチを適用](https://github.com/sensepost/objection/wiki/Patching-Android-Applications#patching---patching-an-apk "patching - patching an APK") して、[Frida ガジェット](https://www.frida.re/docs/gadget/ "Frida Gadget") ライブラリをインクルードします。

これで objection を使用して、非ルート化デバイスでアプリケーションを動的に解析できます。

以下のコマンドは、[Android UnCrackable L1](../../apps/android/MASTG-APP-0003.md) を例として、objection を使用してパッチを適用して動的解析を開始する方法をまとめたものです。

```bash
# Download the Uncrackable APK
$ wget https://raw.githubusercontent.com/OWASP/mastg/master/Crackmes/Android/Level_01/UnCrackable-Level1.apk
# Patch the APK with the Frida Gadget
$ objection patchapk --source UnCrackable-Level1.apk
# Install the patched APK on the android phone
$ adb install UnCrackable-Level1.objection.apk
# After running the mobile phone, objection will detect the running frida-server through the APK
$ objection explore
```
