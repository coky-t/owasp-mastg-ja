---
masvs_category: MASVS-CODE
platform: android
title: デバッグ情報とデバッグシンボル (Debugging Information and Debug Symbols)
---

Android では、ネイティブライブラリは通常、NDK を使用して C または C++ で開発され、.so 拡張子を持つ ELF 共有オブジェクトにコンパイルされ、APK の `lib/` ディレクトリに格納します。これらのライブラリは、多くの場合、Java Native Interface (JNI) を通じて Dalvik から使用される機能を公開します。これらのバイナリ内の **デバッグシンボル** は、関数名、変数名、ソースファイルマッピングなどの詳細を提供し、リバースエンジニアリング、デバッグ、セキュリティ解析に役立ちます。

プログラムをコンパイルおよびリンクする際、シンボルは関数または変数を表します。ELF (Executable and Linkable Format) ファイルでは、シンボルは異なる役割を果たします。

- **ローカルシンボル**: 定義されたファイル内でのみ視認できます。内部的に使用されます。他のファイルからはアクセスできません。
- **グローバルシンボル**: 他のファイルから視認できます。異なるオブジェクトファイル間でファイルや変数を共有するために使用されます。
- **ウィークシンボル**: グローバルシンボルと似ていますが優先度が低くなります。ストロング (非ウィーク) シンボルとウィークシンボルの両方が存在する場合、ストロングシンボルがウィークシンボルをオーバーライドします。

プロダクションビルドでは、バイナリサイズを削減し、情報開示を制限するために、デバッグ情報を削除する必要があります。しかし、デバッグビルドまたは内部ビルドはバイナリ内または別のコンパニオンファイルにシンボルを保持することがあります。

シンボルの可視性は誤って扱われることがよくあり、シンボルの意図しない外部公開につながり、手動検査を必要とします。

## シンボルテーブルと DWARF セクション

[ELF](https://refspecs.linuxfoundation.org/elf/elf.pdf) 形式は、シンボル情報を格納するためにどのセクションを使用する必要があるかを定義しています。

- **`.symtab`**: リンク時に使用される完全なシンボルテーブル。プロダクションバイナリでは削除されることがよくあります (`DT_SYMTAB` dtag)。
- **`.dynsym`**: ランタイムリンク時に使用される動的シンボルテーブル。共有オブジェクトには常に存在します。

[DWARF](https://dwarfstd.org/doc/DWARF5.pdf) は ELF バイナリで使用される標準デバッグ形式です (ただし、Apple エコシステムの MACH-O バイナリなど、他の UNIX ベースのシステムでも使用されています)。主なセクションは以下のとおりです。

- **`.debug_info`**: 型、関数定義、スコープなど、主要なデバッグ情報を含みます。
- **`.debug_line`**: マシンコードをソースコードの行番号にマップします。
- **`.debug_str`**: DWARF エントリで使用される文字列を格納します。
- **`.debug_loc`, `.debug_ranges`, `.debug_abbrev` など**: 詳細なデバッグメタデータをサポートします。

さらに、一部のツールチェーンは DWARF データのバイナリサイズを縮小するために zlib [圧縮](https://www.linker-aliens.org/blogs/ali/entry/elf_section_compression/) を使用します (たとえば [clang](https://clang.llvm.org/docs/ClangCommandLineReference.html#cmdoption-clang-gz) や [gcc](https://gcc.gnu.org/onlinedocs/gcc/Debugging-Options.html#index-gz) は `-gz` オプションを使用してこれをサポートしています)。これらのセクションは一般的に `.z` プレフィックスを使用して名前付けされ (例: `.zdebug_info`, `.zdebug_line`, `.zdebug_str` など)、圧縮されていないセクションと同じ情報を含みます。これらをサポートしていない一部の解析ツールでは、削除されているものとしてバイナリを誤って報告されることがあります。

バイナリ内にこれらのセクションが存在するかどうかをチェックするには、[objdump (iOS)](../../../tools/ios/MASTG-TOOL-0121.md) (`-x` オプションを使用)、[radare2 for Android](../../../tools/android/MASTG-TOOL-0028.md) (`iS` コマンド)、`readelf` などのその他のツールを使用できます。

たとえば、radare2 を使用する場合:

```sh
[0x0003e360]> iS~debug,symtab,SYMTAB
23  0x000c418c      0x60 0x00000000      0x60 ---- 0x0   PROGBITS    .debug_aranges
24  0x000c41ec  0x14d85c 0x00000000  0x14d85c ---- 0x0   PROGBITS    .debug_info
25  0x00211a48    0xa14f 0x00000000    0xa14f ---- 0x0   PROGBITS    .debug_abbrev
26  0x0021bb97   0x5d6a3 0x00000000   0x5d6a3 ---- 0x0   PROGBITS    .debug_line
27  0x0027923a   0x7c26a 0x00000000   0x7c26a ---- 0x30  PROGBITS    .debug_str
28  0x002f54a4  0x172883 0x00000000  0x172883 ---- 0x0   PROGBITS    .debug_loc
29  0x00467d27      0x20 0x00000000      0x20 ---- 0x0   PROGBITS    .debug_macinfo
30  0x00467d47   0x602d0 0x00000000   0x602d0 ---- 0x0   PROGBITS    .debug_ranges
32  0x004c8018   0x27510 0x00000000   0x27510 ---- 0x0   SYMTAB      .symtab
```

**重要**: これらのセクションが存在するからといって、必ずしもバイナリが削除されていないことを示すわけではありません。一部のツールチェーンではストリップされたバイナリでもこれらのセクションを保持することがありますが、多くの場合、空であるか、最低限の情報のみ含みます。最終的に、重要なのは **シンボル自体がまだ存在しているかどうか** です。デバッグシンボルの抽出と解析方法の詳細については [デバッグ情報とシンボルの取得 (Obtaining Debugging Information and Symbols)](../../../techniques/android/MASTG-TECH-0140.md) を参照してください。

## 外部デバッグシンボルファイル

[Android 開発者ドキュメント](https://developer.android.com/build/include-native-symbols) では、リリースビルドのネイティブライブラリはデフォルトで削除されると説明しています。シンボル化されたネイティブクラッシュレポートを有効にするには、別途デバッグシンボルファイル (一般的に `<variant>/native-debug-symbols.zip` にあります) を生成し、Google Play Console にアップロードする必要があります。この ZIP アーカイブは DWARF デバッグ情報を埋め込まれた完全な **削除されていない `.so` ファイル** を含みます。DWARF データは個別のファイル (`.dwo` など) に分割されず、各 `.so` 内に残ります。

> このシンボル化プロセスは ProGuard または R8 で難読化された Java/Kotlin コードの [スタックトレースの難読化解除](https://support.google.com/googleplay/android-developer/answer/9848633) するために `mapping.txt` ファイルをアップロードすることに似ています。

対照的に、iOS は Linux ツールチェーンでおなじみの [split DWARF](https://clang.llvm.org/docs/ClangCommandLineReference.html#cmdoption-clang-gsplit-dwarf) と **精神的に似た** アプローチを使用しています。[Apple 開発者ドキュメント](https://developer.apple.com/documentation/xcode/building-your-app-to-include-debugging-information) に従って、Xcode で `DWARF with dSYM File` オプションを有効にすると、リリースビルド用に個別のデバッグシンボルファイル (`.dSYM`) を生成します。これらはクラッシュレポートのシンボル化のために Apple のシンボルサーバーにアップロードできます。
