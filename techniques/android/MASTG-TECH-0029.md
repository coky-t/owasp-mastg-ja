---
title: ロードされたネイティブライブラリのリスト (Listing Loaded Native Libraries)
platform: android
---

この技法は、実行中の Android アプリによってメモリにロードされたネイティブライブラリを特定して抽出する方法について説明します。APK からネイティブライブラリを静的に特定する [バンドルされているネイティブライブラリの抽出 (Extracting Bundled Native Libraries)](MASTG-TECH-0157.md) とは異なり、このアプローチはデバイス上で実行されているアプリを必要となります。

## [adb](../../tools/android/MASTG-TOOL-0004.md) を使用する

Linux カーネルは仮想ファイル `/proc/<pid>/maps` を通じて全プロセスのメモリマップを公開しています。各行は一つのマップされた領域を表し、仮想アドレス範囲、メモリパーミッション (`r`ead/`w`rite/e`x`ecute/`p`rivate/`s`hared)、backing ファイル内のオフセット、デバイス、inode、パス名を含みます。

adb を使用して、対象プロセスのこのファイルを読み取ります (`adb root` が必要とされます):

```bash
adb shell cat /proc/23796/maps | grep "/data/.*\.so"
7619ca3000-7619e68000 r-xp 00000000 fe:27 352366                         /data/data/org.owasp.mastestapp/code_cache/startup_agents/dced2491-agent.so
7619e6b000-7619e79000 r--p 001c8000 fe:27 352366                         /data/data/org.owasp.mastestapp/code_cache/startup_agents/dced2491-agent.so
7619e7c000-7619eb8000 rw-p 001d5000 fe:27 352366                         /data/data/org.owasp.mastestapp/code_cache/startup_agents/dced2491-agent.so
...
```

## [Frida (Android)](../../tools/android/MASTG-TOOL-0001.md) を使用する

`Process.enumerateModules` を使用して、プロセスメモリにロードされたライブラリをリストすることで、Frida CLI から直接プロセス関連情報を取得できます。

```bash
[Android Emulator 5554::MASTestApp ]-> Process.enumerateModules()
[
   {
        "base": "0x766af82000",
        "name": "libcutils.so",
        "path": "/apex/com.android.vndk.v34/lib64/libcutils.so",
        "size": 204800,
        "version": null
    },
    {
        "base": "0x7668523000",
        "name": "libc++.so",
        "path": "/apex/com.android.vndk.v34/lib64/libc++.so",
        "size": 827392,
        "version": null
    },
...
]
```
