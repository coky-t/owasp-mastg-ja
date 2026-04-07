---
title: コンパイラが提供するセキュリティ機能の取得 (Obtaining Compiler-Provided Security Features)
platform: ios
---

iOS コンパイラはコンパイル時に有効化できる複数のセキュリティ機能を提供します ([バイナリ保護メカニズム (Binary Protection Mechanisms)](../../../knowledge/ios/MASVS-CODE/MASTG-KNOW-0061.md) を参照)。これらの機能はバッファオーバーフローやメモリリークといった一般的な脆弱性からアプリケーションを保護するのに役立ちます。この技法はこれらの機能がコンパイル済みバイナリで有効になっているかどうかをチェックする方法を説明します。

## [radare2 (iOS)](../../tools/ios/MASTG-TOOL-0073.md)

radare2 では、コンパイラが提供するこれらのセキュリティ機能の有無は `i` コマンドと `is` コマンドを使用してチェックできます。

**PIC とカナリアのチェック:** `i` コマンドを使用すると、バイナリが位置独立コード (Position Independent Code, PIC) を有効化されているか (`pic`)、スタックカナリアを有しているか (`canary`) をチェックできます。

```sh
r2 MASTestApp
[0x100007408]> i~canary,pic
canary   true
pic      true
```

この出力はスタックカナリアと PIE が有効になっていることを示しています。

**ARC のチェック** `is` コマンドを使用すると、バイナリ内のシンボルをリストし、自動参照カウント (Automatic Reference Counting, ARC) の使用を示すシンボルをチェックできます。一般的な ARC シンボルには以下があります。

- `objc_autorelease`
- `objc_retainAutorelease`
- `objc_release`
- `objc_retain`
- `objc_retainAutoreleasedReturnValue`
- `swift_release`
- `swift_retain`

iOS バイナリは ARC 有効とみなされるためにこれらのシンボルのすべてを有する必要はありませんが、それらの一部が存在することで ARC が使用されていることを示します。

```sh
[0x100007408]> is~release,retain
80  0x0000790c 0x10000790c LOCAL  FUNC 0        imp.objc_release_x20
81  0x00007918 0x100007918 LOCAL  FUNC 0        imp.objc_release_x24
82  0x00007924 0x100007924 LOCAL  FUNC 0        imp.objc_release_x25
83  0x00007930 0x100007930 LOCAL  FUNC 0        imp.objc_release_x27
84  0x0000793c 0x10000793c LOCAL  FUNC 0        imp.objc_release_x8
85  0x00007948 0x100007948 LOCAL  FUNC 0        imp.objc_retainAutoreleasedReturnValue
86  0x00007954 0x100007954 LOCAL  FUNC 0        imp.objc_retain_x23
101 0x00007a08 0x100007a08 LOCAL  FUNC 0        imp.swift_release
102 0x00007a14 0x100007a14 LOCAL  FUNC 0        imp.swift_retain
```

この出力はバイナリが ARC 使用を示すシンボルを含むことを示しています。

## [objection (iOS)](../../tools/ios/MASTG-TOOL-0074.md)

objection は `ios info binary` コマンドがあり、スタックカナリアや PIE が有効になっているかどうかなど、バイナリに関する情報を取得するために使用できます。

```sh
com.yourcompany.PPClient on (iPhone: 13.2.3) [usb] # ios info binary
Name                  Type     Encrypted    PIE    ARC    Canary    Stack Exec    RootSafe
--------------------  -------  -----------  -----  -----  --------  ------------  ----------
PayPal                execute  True         True   True   True      False         False
CardinalMobile        dylib    False        False  True   True      False         False
FraudForce            dylib    False        False  True   True      False         False
...
```

この出力は `PIE`, `ARC`, `Canary` を `True` または `False` の値で示しています。
