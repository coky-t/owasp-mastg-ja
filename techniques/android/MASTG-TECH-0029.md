---
title: ロードされたネイティブライブラリの取得 (Get Loaded Native Libraries)
platform: android
---

## プロセスメモリマップの使用

ファイル `/proc/<pid>/maps` には現在マップされているメモリ領域とアクセスパーミッションを含みます。このファイルを使用して、プロセスにロードされたライブラリのリストを取得できます。

```bash
# cat /proc/9568/maps
12c00000-52c00000 rw-p 00000000 00:04 14917                              /dev/ashmem/dalvik-main space (region space) (deleted)
6f019000-6f2c0000 rw-p 00000000 fd:00 1146914                            /data/dalvik-cache/arm64/system@framework@boot.art
...
7327670000-7329747000 r--p 00000000 fd:00 1884627                        /data/app/com.google.android.gms-4FJbDh-oZv-5bCw39jkIMQ==/oat/arm64/base.odex
..
733494d000-7334cfb000 r-xp 00000000 fd:00 1884542                        /data/app/com.google.android.youtube-Rl_hl9LptFQf3Vf-JJReGw==/lib/arm64/libcronet.80.0.3970.3.so
...
```

## Frida の使用

Frida CLI から `Process` コマンドを使用してプロセスに関連する情報を直接取得できます。`Process` コマンド内では、`enumerateModules` 関数がプロセスメモリにロードされたライブラリをリストします。

```bash
[Huawei Nexus 6P::sg.vantagepoint.helloworldjni]-> Process.enumerateModules()
[
    {
        "base": "0x558a442000",
        "name": "app_process64",
        "path": "/system/bin/app_process64",
        "size": 32768
    },
    {
        "base": "0x78bc984000",
        "name": "libandroid_runtime.so",
        "path": "/system/lib64/libandroid_runtime.so",
        "size": 2011136
    },
...

```
