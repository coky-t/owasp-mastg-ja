---
title: コードを Smali へ逆アセンブル (Disassembling Code to Smali)
platform: android
---

アプリの smali コードを (Java の代わりに) 検査したい場合は、"Welcome screen" から **Profile or debug APK** をクリックして [Android Studio で APK を開く](https://developer.android.com/studio/debug/apk-debugger "Debug pre-built APKs") ことができます (デバッグするつもりがなくても、smali コードを確認できます)。

あるいは、[Apktool](../../tools/android/MASTG-TOOL-0011.md) を使用して、APK アーカイブから直接リソースを抽出して逆アセンブルし、Java バイトコードを smali に逆アセンブルできます。apktool はパッケージを再アセンブルできるため、アプリを [パッチ適用 (Patching)](MASTG-TECH-0038.md) したり、Android Manifest などの変更を適用するのに役立ちます。
