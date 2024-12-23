---
title: コンパイラが提供するセキュリティ機能の取得 (Obtaining Compiler-Provided Security Features)
platform: android
---

ターゲットバイナリ (共有ライブラリなど) に対して [radare2 for Android](../../tools/android/MASTG-TOOL-0028.md) を実行し、チェックしたいキーワードを grep します。

```sh
rabin2 -I lib/x86_64/libnative-lib.so | grep -E "canary|pic"
canary   false
```
