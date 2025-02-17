---
title: コード署名フォーマットバージョンの取得 (Obtaining the Code Signature Format Version)
platform: ios
---

署名されたバイナリからコード署名フォーマットバージョンを抽出するには、[codesign](../../tools/ios/MASTG-TOOL-0114.md) を使用できます。

バージョンは `codesign -dv` を呼び出して `CodeDirectory` 行の `v` の値を識別することで取得します。

```bash
$ codesign -dv MASTestApp.app
Executable=/Users/user/MASTestApp.app
Identifier=org.owasp.mastestapp.MASTestApp-iOS
Format=Mach-O universal (armv7 arm64)
CodeDirectory v=20400 size=404674 flags=0x0(none) hashes=12635+7 location=embedded
Signature size=4858
...
```

このケースでは、出力に `v=20400` を含むため、バージョンは 20400 です。
