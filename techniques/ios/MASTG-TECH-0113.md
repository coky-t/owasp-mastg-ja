---
title: デバッグシンボルの取得 (Obtaining Debugging Symbols)
platform: ios
---

iOS バイナリからデバッグシンボルを取得するには、[radare2 (iOS)](../../tools/ios/MASTG-TOOL-0073.md)、[objdump (iOS)](../../tools/ios/MASTG-TOOL-0121.md)、または [nm (iOS)](../../tools/ios/MASTG-TOOL-0041.md) を使用して、すべてのアプリバイナリを検査できます。

## radare2

[radare2 (iOS)](../../tools/ios/MASTG-TOOL-0073.md) をコマンド `is` とともに使用します。

```bash
r2 -A MASTestApp
[0x100007408]> is~Sec
70  0x00007894 0x100007894 LOCAL  FUNC 0        imp.SecKeyCopyExternalRepresentation
71  0x000078a0 0x1000078a0 LOCAL  FUNC 0        imp.SecKeyCopyPublicKey
72  0x000078ac 0x1000078ac LOCAL  FUNC 0        imp.SecKeyCreateRandomKey
73  0x000078b8 0x1000078b8 LOCAL  FUNC 0        imp.SecKeyCreateSignature
74  0x000078c4 0x1000078c4 LOCAL  FUNC 0        imp.SecKeyVerifySignature
```

あるいは、[rabin2](../../tools/generic/MASTG-TOOL-0129.md) を使用して、`rabin2 -s MASTestApp` を実行することによって [シンボルを取得](https://book.rada.re/tools/rabin2/symbols.html) できます。

## objdump

以下のスニペットは、デバッグシンボルを含むバイナリの典型的な出力として、`MASTestApp` (iOS メインアプリ実行ファイル) に [objdump (iOS)](../../tools/ios/MASTG-TOOL-0121.md) を適用する方法を示しています。それらは `d` (デバッグ) フラグでマークされています。さまざまなその他のシンボルフラグ文字についての情報には [objdump マニュアルページ](https://www.unix.com/man-page/osx/1/objdump/ "objdump man page") をチェックしてください。

```bash
$ objdump --syms MASTestApp | grep " d " | grep "swift"
...
0000000000000000      d  *UND* MastgTest.swift
0000000000000000      d  *UND* __swift_FORCE_LOAD_$_swiftFoundation_$_MASTestApp
0000000000000000      d  *UND* __swift_FORCE_LOAD_$_swiftObjectiveC_$_MASTestApp
0000000000000000      d  *UND* __swift_FORCE_LOAD_$_swiftDarwin_$_MASTestApp
0000000000000000      d  *UND* __swift_FORCE_LOAD_$_swiftCoreFoundation_$_MASTestApp
...
```

## nm

[nm (iOS)](../../tools/ios/MASTG-TOOL-0041.md) では、プレーンな `nm` の呼び出しからのシンボルと `nm -a` の呼び出しの出力を比較できます。後者はデバッグシンボルも出力します。以下のコマンドはデバッグシンボルのみを diff 形式で表示します。これが空の場合、デバッグシンボルは存在しません。

```bash
$ diff <(nm MASTestApp) <(nm -a MASTestApp)
...
28a228
> 0000000100009928 - 01 0000   FUN _$s10MASTestApp11ContentViewV7SwiftUI0D0AadEP05_makeD4List4view6inputsAD01_dH7OutputsVAD11_GraphValueVyxG_AD01_dH6InputsVtFZTW
30a231
> 000000010000992c - 01 0000   FUN _$s10MASTestApp11ContentViewV7SwiftUI0D0AadEP14_viewListCount6inputsSiSgAD01_dhI6InputsV_tFZTW
31a233,234
> 0000000100009944 - 01 0000   FUN _$s10MASTestApp11ContentViewV7SwiftUI0D0AadEP4body4BodyQzvgTW
> 0000000000000000 - 00 0000  GSYM _$s10MASTestApp11ContentViewVAC7SwiftUI0D0AAWL
32a236
> 000000010000a220 - 01 0000   FUN _$s10MASTestApp11ContentViewVAC7SwiftUI0D0AAWl
...
```
