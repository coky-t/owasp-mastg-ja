---
masvs_v1_id:
- MSTG-CODE-9
masvs_v2_id:
- MASVS-CODE-4
platform: ios
title: フリーなセキュリティ機能が有効であることの確認 (Make Sure That Free Security Features Are Activated)
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
status: deprecated
covered_by: [MASTG-TEST-0228, MASTG-TEST-0229, MASTG-TEST-0230]
deprecation_note: New version available in MASTG V2
---

## 概要

## 静的解析

radare2 を使用してバイナリセキュリティ機能をチェックできます。

例として [Damn Vulnerable iOS App DVIA v1](https://github.com/prateek147/DVIA/) を使用してみましょう。radare2 でそのメインバイナリを開きます。

```bash
r2 DamnVulnerableIOSApp
```

そして以下のコマンドを実行します。

```bash
[0x1000180c8]> i~pic,canary
canary   true
pic      true
```

```bash
[0x1000180c8]> is~release,retain
124  0x002951e0 0x1000891e0 LOCAL  FUNC 0        imp.dispatch_release
149  0x00294e80 0x100088e80 LOCAL  FUNC 0        imp.objc_autorelease
150  0x00294e8c 0x100088e8c LOCAL  FUNC 0        imp.objc_autoreleasePoolPop
151  0x00294e98 0x100088e98 LOCAL  FUNC 0        imp.objc_autoreleasePoolPush
152  0x00294ea4 0x100088ea4 LOCAL  FUNC 0        imp.objc_autoreleaseReturnValue
165  0x00294f40 0x100088f40 LOCAL  FUNC 0        imp.objc_release
167  0x00294f58 0x100088f58 LOCAL  FUNC 0        imp.objc_retainAutorelease
168  0x00294f64 0x100088f64 LOCAL  FUNC 0        imp.objc_retainAutoreleaseReturnValue
169  0x00294f70 0x100088f70 LOCAL  FUNC 0        imp.objc_retainAutoreleasedReturnValue
```

これらの例ではすべての機能が有効になっています。

- 位置独立コード (PIE, Position Independent Executable): `pic true` フラグによって示されます。
    - 使用する言語に関係なく、すべてのアプリに適用されます。
    - メインの実行可能ファイル (`MH_EXECUTE`) にのみ適用され、動的ライブラリ (`MH_DYLIB`) には適用されません。

- スタックカナリア (Stack Canary): `canary true` フラグによって示されます。
    - Objective-C コードを含むアプリに適用されます。
    - 純粋な Swift アプリには必要ありません (Swift は設計上メモリセーフです)。
    - C/C++ コードを含むアプリでは特に重要です。アプリはメモリやポインタへの直接アクセスを提供して、バッファオーバーフローに対してより脆弱になるためです。

- 自動参照カウント (ARC, Automatic Reference Counting): `objc_autorelease` や `objc_retainAutorelease` などのシンボルによって示されます。
    - Objective-C コードを含むバイナリにとって重要です。
    - 純粋に Swift で書かれたバイナリでは、ARC はデフォルトで有効になります。
    - ARC は Objective-C と Swift に固有のメモリ管理機能なので、純粋に C/C++ で記述されたバイナリには関係ありません。

## 動的解析

これらのチェックは [objection](../../../tools/generic/MASTG-TOOL-0038.md) を使用して動的に実行できます。以下はその一例です。

```bash
com.yourcompany.PPClient on (iPhone: 13.2.3) [usb] # ios info binary
Name                  Type     Encrypted    PIE    ARC    Canary    Stack Exec    RootSafe
--------------------  -------  -----------  -----  -----  --------  ------------  ----------
PayPal                execute  True         True   True   True      False         False
CardinalMobile        dylib    False        False  True   True      False         False
FraudForce            dylib    False        False  True   True      False         False
...
```
