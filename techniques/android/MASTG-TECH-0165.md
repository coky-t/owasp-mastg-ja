---
title: Android アプリのコンパイラ、難読化、パッカーの識別 (Identifying Compilers, Obfuscators, and Packers in Android Apps)
platform: android
---

[APKiD](../../tools/android/MASTG-TOOL-0009.md) を使用して、APK をスキャンし、適用されているコンパイラ、難読化、パッカーを特定します。

```bash
apkid YourApp.apk
```

APKiD は APK 内の DEX ファイルを、既知のコンパイラ、難読化、パッカーによって残されたシグネチャについて検査します。出力には、DEX ごと、および、存在する場合には、ネイティブライブラリごとに一致情報をリストします。

[Android UnCrackable L4](../../apps/android/MASTG-APP-0015.md) を使用した例:

```bash
apkid ./r2pay-v1.0.apk

[+] APKiD 3.1.0 :: from RedNaga :: rednaga.io
[*] /input/r2pay-v1.0.apk!classes.dex
 |-> anti_vm : Build.TAGS check, possible ro.secure check
 |-> compiler : r8
 |-> obfuscator : unreadable field names, unreadable method names
[*] /input/r2pay-v1.0.apk!lib/arm64-v8a/libnative-lib.so
 |-> obfuscator : Obfuscator-LLVM version unknown (string encryption)
[*] /input/r2pay-v1.0.apk!lib/armeabi-v7a/libnative-lib.so
 |-> obfuscator : Obfuscator-LLVM version unknown (string encryption)
[*] /input/r2pay-v1.0.apk!lib/armeabi-v7a/libtool-checker.so
 |-> anti_root : RootBeer
[*] /input/r2pay-v1.0.apk!lib/x86_64/libnative-lib.so
 |-> obfuscator : Obfuscator-LLVM version unknown (string encryption)
[*] /input/r2pay-v1.0.apk!lib/x86_64/libtool-checker.so
 |-> anti_root : RootBeer
```

各一致項目について、保護の種類 (例: `compiler`, `obfuscator`, `packer`, `anti_vm`, `anti_root`)、特定されたツールや技法の名称、関連する詳細 (例: バージョン、検出された特定の機能) を示します。

難読化器やパッカーが特定されない場合には、コンパイラの項目のみが現れます。`obfuscator` や `packer` の項目がないことは、そのコードが既知のツールによって保護されていないことを示しています。
