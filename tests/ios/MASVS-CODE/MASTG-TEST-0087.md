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
---

## 概要

## 静的解析

[otool](../../../Document/0x08a-Testing-Tools.md#otool) を使用して上記のバイナリセキュリティ機能をチェックできます。これらの例ではすべての機能が有効になっています。

- PIE:

    ```bash
    $ unzip DamnVulnerableiOSApp.ipa
    $ cd Payload/DamnVulnerableIOSApp.app
    $ otool -hv DamnVulnerableIOSApp
    DamnVulnerableIOSApp (architecture armv7):
    Mach header
    magic cputype cpusubtype caps filetype ncmds sizeofcmds flags
    MH_MAGIC ARM V7 0x00 EXECUTE 38 4292 NOUNDEFS DYLDLINK TWOLEVEL
    WEAK_DEFINES BINDS_TO_WEAK PIE
    DamnVulnerableIOSApp (architecture arm64):
    Mach header
    magic cputype cpusubtype caps filetype ncmds sizeofcmds flags
    MH_MAGIC_64 ARM64 ALL 0x00 EXECUTE 38 4856 NOUNDEFS DYLDLINK TWOLEVEL
    WEAK_DEFINES BINDS_TO_WEAK PIE
    ```

    この出力結果は `PIE` の Mach-O フラグが設定されていることを示しています。このチェックは Objective-C, Swift, ハイブリッドアプリのすべてに適用されますが、メインの実行可能ファイルにのみ適用されます。

- Stack canary:

    ```bash
    $ otool -Iv DamnVulnerableIOSApp | grep stack
    0x0046040c 83177 ___stack_chk_fail
    0x0046100c 83521 _sigaltstack
    0x004fc010 83178 ___stack_chk_guard
    0x004fe5c8 83177 ___stack_chk_fail
    0x004fe8c8 83521 _sigaltstack
    0x00000001004b3fd8 83077 ___stack_chk_fail
    0x00000001004b4890 83414 _sigaltstack
    0x0000000100590cf0 83078 ___stack_chk_guard
    0x00000001005937f8 83077 ___stack_chk_fail
    0x0000000100593dc8 83414 _sigaltstack
    ```

    上記の出力結果で `__stack_chk_fail` の存在はスタックカナリアが使用されていることを示しています。このチェックは純粋な Objective-C アプリとハイブリッドアプリに適用できますが、純粋な Swift アプリには適用できません (つまり Swift は設計上、メモリセーフであるため無効と表示されていても問題ありません) 。

- ARC:

    ```bash
    $ otool -Iv DamnVulnerableIOSApp | grep release
    0x0045b7dc 83156 ___cxa_guard_release
    0x0045fd5c 83414 _objc_autorelease
    0x0045fd6c 83415 _objc_autoreleasePoolPop
    0x0045fd7c 83416 _objc_autoreleasePoolPush
    0x0045fd8c 83417 _objc_autoreleaseReturnValue
    0x0045ff0c 83441 _objc_release
    [SNIP]
    ```

    このチェックは自動的に有効になる純粋な Swift アプリを含むすべてのケースに適用できます。

## 動的解析

これらのチェックは [objection](../../../Document/0x08a-Testing-Tools.md#objection) を使用して動的に実行できます。以下はその一例です。

```bash
com.yourcompany.PPClient on (iPhone: 13.2.3) [usb] # ios info binary
Name                  Type     Encrypted    PIE    ARC    Canary    Stack Exec    RootSafe
--------------------  -------  -----------  -----  -----  --------  ------------  ----------
PayPal                execute  True         True   True   True      False         False
CardinalMobile        dylib    False        False  True   True      False         False
FraudForce            dylib    False        False  True   True      False         False
...
```
