---
title: コンパイラが提供するセキュリティ機能の取得 (Obtaining Compiler-Provided Security Features)
platform: android
---

ターゲットバイナリ (共有ライブラリなど) に対して [rabin2](../../tools/generic/MASTG-TOOL-0129.md) を実行し、チェックしたいキーワードを grep します。

```sh
rabin2 -I lib/x86_64/libnative-lib.so | grep -E "canary|pic"
canary   false
```
