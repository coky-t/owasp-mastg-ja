---
masvs_v1_id:
- MSTG-CODE-3
masvs_v2_id:
- MASVS-RESILIENCE-3
platform: ios
title: デバッグシンボルのテスト (Testing for Debugging Symbols)
masvs_v1_levels:
- R
---

## 概要

## 静的解析

デバッグシンボルの存在を検証するには [binutils](https://www.gnu.org/s/binutils/ "Binutils") の objdump または [llvm-objdump](https://llvm.org/docs/CommandGuide/llvm-objdump.html "llvm-objdump") を使用してすべてのアプリバイナリを検査できます。

以下のスニペットでは `TargetApp` (iOS メインアプリ実行可能ファイル) に対して objdump を実行して `d` (debug) フラグでマークされたデバッグシンボルを含むバイナリの典型的な出力を示しています。その他のさまざまなシンボルフラグ文字については [objdump man page](https://www.unix.com/man-page/osx/1/objdump/ "objdump man page") を確認してください。

```bash
$ objdump --syms TargetApp

0000000100007dc8 l    d  *UND* -[ViewController handleSubmitButton:]
000000010000809c l    d  *UND* -[ViewController touchesBegan:withEvent:]
0000000100008158 l    d  *UND* -[ViewController viewDidLoad]
...
000000010000916c l    d  *UND* _disable_gdb
00000001000091d8 l    d  *UND* _detect_injected_dylds
00000001000092a4 l    d  *UND* _isDebugged
...
```

デバッグシンボルが含まれないようにするには、 XCode プロジェクトのビルド設定で `Strip Debug Symbols During Copy` を `YES` に設定します。デバッグシンボルを削除するとバイナリサイズが小さくなるだけでなく、リバースエンジニアリングの難易度が上がります。

## 動的解析

動的解析はデバッグシンボルの検索には適用できません。
