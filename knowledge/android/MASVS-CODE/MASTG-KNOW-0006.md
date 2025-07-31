---
masvs_category: MASVS-CODE
platform: android
title: バイナリ保護メカニズム (Binary Protection Mechanisms)
---

[バイナリ保護メカニズム](../../../Document/0x04h-Testing-Code-Quality.md#binary-protection-mechanisms) の存在を検出することはアプリケーションの開発に使用された言語に大きく依存します。

一般的にはすべてのバイナリをテストすべきです。これにはメインのアプリ実行可能ファイルだけでなくすべてのライブラリや依存関係が含まれます。しかし、Android では次に説明するようにメインの実行可能ファイルは安全であると考えられるため、ネイティブライブラリに焦点を当てます。

Android は アプリの DEX ファイル (classes.dex など) から Dalvik バイトコードを最適化し、ネイティブコードを含む新しいファイルを生成します。通常、拡張子は .odex, .oat です。この Android コンパイル済みバイナリ ([アプリバイナリの探索 (Exploring the App Package)](../../../techniques/android/MASTG-TECH-0007.md) の "コンパイル済みアプリバイナリ" を参照) は Linux や Android がアセンブリコードをパッケージ化するために使用するフォーマットである [ELF フォーマット](https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html) を使用してラップされています。

アプリの NDK ネイティブライブラリ ([アプリバイナリの探索 (Exploring the App Package)](../../../techniques/android/MASTG-TECH-0007.md) の "ネイティブライブラリ" を参照) も [ELF フォーマットを使用](https://developer.android.com/ndk/guides/abis) しています。

- [**PIE (Position Independent Executable)**](../../../Document/0x04h-Testing-Code-Quality.md#position-independent-code):
    - Android 7.0 (API レベル 24) 以降、メインの実行可能ファイルに対して PIC コンパイルは [デフォルトで有効](https://source.android.com/devices/tech/dalvik/configure) になっています。
    - Android 5.0 (API レベル 21) で PIE 非対応のネイティブライブラリのサポートは [廃止](https://source.android.com/security/enhancements/enhancements50) され、それ以降 PIE は [リンカーによって強制](https://cs.android.com/android/platform/superproject/+/master:bionic/linker/linker_main.cpp;l=430) されるようになりました。
- [**メモリ管理**](../../../Document/0x04h-Testing-Code-Quality.md#memory-management):
    - ガベージコレクションはメインのバイナリに対して実行されるだけで、バイナリ自体は何もチェックされません。
    - ガベージコレクションは Android ネイティブライブラリには適用されません。開発者は適切な [手動メモリ管理](../../../Document/0x04h-Testing-Code-Quality.md#manual-memory-management) を行う責任があります。 ["メモリ破損バグ"](../../../Document/0x04h-Testing-Code-Quality.md#memory-corruption-bugs) を参照してください。
- [**スタックスマッシュ保護**](../../../Document/0x04h-Testing-Code-Quality.md#stack-smashing-protection):
    - Android アプリはメモリセーフと考えられる (少なくともバッファオーバーフローを軽減する) Dalvik バイトコードにコンパイルされます。Flutter などの他のフレームワークはその言語 (この場合は Dart) がバッファーオーバーフローを軽減する方法であるため、スタックカナリアを使用したコンパイルは行われません。
    - Android ネイティブライブラリは有効にしなければなりませんが、それを完全に判断するのは難しいかもしれません。
        - NDK ライブラリはコンパイラがデフォルトでそれを行うため有効になっているはずです。
        - 他のカスタム C/C++ ライブラリは有効になっていない可能性があります。

詳しくはこちら。

- [Android executable formats](https://lief-project.github.io/doc/latest/tutorials/10_android_formats.html)
- [Android runtime (ART)](https://source.android.com/devices/tech/dalvik/configure#how_art_works)
- [Android NDK](https://developer.android.com/ndk/guides)
- [Android linker changes for NDK developers](https://android.googlesource.com/platform/bionic/+/master/android-changes-for-ndk-developers.md)
