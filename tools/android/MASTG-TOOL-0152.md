---
title: lldb (Android)
platform: android
source: https://lldb.llvm.org/
hosts: [windows, linux, macOS]
---

[lldb](https://lldb.llvm.org/) は LLVM デバッガです。Android では、JNI ライブラリ、ネイティブキャッシュ、メモリ、レジスタ、システムコール、コンパイル済み制御フローなど、アプリ内のネイティブコードをデバッグに使用できます。

lldb を使用して、実行中のプロセスにアタッチしたり、デバッガでアプリを起動できます。コマンドラインワークフローは一般的に Android Studio または Android NDK ([Android NDK](MASTG-TOOL-0005.md)) の lldb クライアントを、デバイス上で動作する `lldb-server` バイナリと併せて、使用します。

## 要件と使用上の注意

- デバッグ可能なアプリ、適切なテストビルド、root などの十分なデバイス権限を必要とします。
- アプリはデバッガアタッチメント、ルート、ptrace の使用、タイミングの変更、フックフレームワークを検出できることがあります。
- ネイティブデバッガがアタッチされるまでプロセスの生成をブロックするには、一般的に lldb と Java または JDWP ベースの起動制御を組み合わせる必要があります。
- 可能であれば、ホストサイドの lldb クライアントと一致するデバイスサイドの `lldb-server` バージョンを使用します。

デバイスサイドの `lldb-server` バイナリは一般的に以下のようなパスに位置します。

```bash
$LLDB_ROOT/toolchains/llvm/prebuilt/$HOST_ARCH/lib/clang/$CLANG_VERSION/lib/linux/$ANDROID_ARCH/lldb-server
````

このパスは、Android Studio、NDK、ホストプラットフォーム、LLVM によって異なることがあります。それを見つけるには、Android SDK または NDK ディレクトリ内を検索します。

```bash
find "$ANDROID_HOME" "$ANDROID_NDK_HOME" -name lldb-server 2>/dev/null
```

一致するバイナリを見つけたら、それをデバイスにアップロードして実行可能としてマークします。たとえば以下のようになります。

```bash
adb push lldb-server /data/local/tmp/
adb shell chmod +x /data/local/tmp/lldb-server
```

## Android 14 (API レベル 34) 互換性に関する注意

一部のユーザーが、特定の lldb クライアントで Android 14 (API レベル 34) 以降のプロセスをデバッグする際のクラッシュを報告しています。報告されているワークアラウンドは、JIT ローダープラグインを無効にし、デバッガをアタッチしたまま `SIGSEGV` および `SIGBUS` を渡すことです。

```bash
(lldb) settings set plugin.jit-loader.gdb.enable off
(lldb) process handle SIGSEGV -s false -p true -n false
(lldb) process handle SIGBUS -s false -p true -n false
```

セットアップと使用方法については、Android 公式ドキュメントの [アプリをデバッグする](https://developer.android.com/studio/debug)、[NDK デバッグ](https://developer.android.com/ndk/guides/ndk-gdb)、[Android Studio 実行/デバッグ構成](https://developer.android.com/studio/run/rundebugconfig) を参照してください。デバッグ可能なアプリとデバッグ不可能なアプリに lldb をアタッチする手順の例については、[デバッグ (Debugging)](../../techniques/android/MASTG-TECH-0031.md) を参照してください。
