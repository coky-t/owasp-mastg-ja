---
title: dsdump
platform: ios
source: https://github.com/DerekSelander/dsdump
---

[dsdump](https://github.com/DerekSelander/dsdump "dsdump") は Objective-C クラスと Swift 型記述子 (クラス、構造体、列挙型) をダンプするツールです。Swift バージョン 5 以降のみをサポートしており、ARM 32 ビットバイナリはサポートしていません。

以下の例は、iOS アプリケーションの Objective-C クラスと Swift 型記述子をダンプする方法を示しています。

まず、アプリのメインバイナリが ARM64 を含む FAT バイナリであるかどうかを確認します。

```bash
$ otool -hv [APP_MAIN_BINARY_FILE]
Mach header
      magic cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
   MH_MAGIC     ARM         V7  0x00     EXECUTE    39       5016   NOUNDEFS DYLDLINK TWOLEVEL PIE
Mach header
      magic cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64   ARM64        ALL  0x00     EXECUTE    38       5728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```

含む場合、"--arch" パラメータに "arm64" を指定します。そうではなく、そのバイナリが ARM64 バイナリのみを含む場合は必要ありません。

```bash
# Dump the Objective-C classes to a temporary file
$ dsdump --objc --color --verbose=5 --arch arm64 --defined [APP_MAIN_BINARY_FILE] > /tmp/OBJC.txt

# Dump the Swift type descriptors to a temporary file if the app is implemented in Swift
$ dsdump --swift --color --verbose=5 --arch arm64 --defined [APP_MAIN_BINARY_FILE] > /tmp/SWIFT.txt
```

dsdump の内部動作と、コンパイルされた Swift の型と Objective-C クラスを表示するために Mach-O バイナリをプログラムで調査する方法の詳細については、[この記事](https://derekselander.github.io/dsdump/ "Building a class-dump in 2020") を参照してください。
