---
masvs_v1_id:
- MSTG-CODE-9
masvs_v2_id:
- MASVS-CODE-4
platform: android
title: フリーのセキュリティ機能が有効であることの確認 (Make Sure That Free Security Features Are Activated)
masvs_v1_levels:
- L1
- L2
---

## 概要

## 静的解析

アプリのネイティブライブラリをテストして、PIE とスタックスマッシュ保護が有効になっているかどうかを確認します。

[radare2 の rabin2](../../../Document/0x08a-Testing-Tools.md#radare2) を使用してバイナリ情報を取得できます。例として [UnCrackable App for Android Level 4](../../../Document/0x08b-Reference-Apps.md#android-uncrackable-l4) v1.0 APK を使用します。

すべてのネイティブライブラリは `canary` と `pic` が両方とも `true` に設定されていなければなりません。

これは `libnative-lib.so` のケースです。

```sh
rabin2 -I lib/x86_64/libnative-lib.so | grep -E "canary|pic"
canary   true
pic      true
```

しかし `libtool-checker.so` はそうではありません。

```sh
rabin2 -I lib/x86_64/libtool-checker.so | grep -E "canary|pic"
canary   false
pic      true
```

この例では `libtool-checker.so` はスタックスマッシュ保護サポートありで再コンパイルしなければなりません。
