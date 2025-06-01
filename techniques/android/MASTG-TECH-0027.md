---
title: オープンファイルの取得 (Get Open Files)
platform: android
---

`lsof` に `-p <pid>` フラグを付けて使用すると、指定したプロセスのオープンファイルのリストを返します。オプションの詳細は [man ページ](http://man7.org/linux/man-pages/man8/lsof.8.html "Man Page of lsof") を参照してください。

```bash
# lsof -p 6233
COMMAND     PID       USER   FD      TYPE             DEVICE  SIZE/OFF       NODE NAME
.foobar.c  6233     u0_a97  cwd       DIR                0,1         0          1 /
.foobar.c  6233     u0_a97  rtd       DIR                0,1         0          1 /
.foobar.c  6233     u0_a97  txt       REG             259,11     23968        399 /system/bin/app_process64
.foobar.c  6233     u0_a97  mem   unknown                                         /dev/ashmem/dalvik-main space (region space) (deleted)
.foobar.c  6233     u0_a97  mem       REG              253,0   2797568    1146914 /data/dalvik-cache/arm64/system@framework@boot.art
.foobar.c  6233     u0_a97  mem       REG              253,0   1081344    1146915 /data/dalvik-cache/arm64/system@framework@boot-core-libart.art
...
```

上記の出力で、私たちにとって最も重要なフィールドは以下のとおりです。

- `NAME`: ファイルのパス。
- `TYPE`: ファイルの種類。たとえば、ファイルがディレクトリであるか、通常のファイルであるか。

これは、難読化や他のアンチリバースエンジニアリング技法を使用しているアプリケーションを監視する際に、コードをリバースすることなく、異常なファイルを見つけるのに非常に役立ちます。たとえば、アプリケーションがデータの暗号化と復号化を実行して、それを一時的にファイルに保存していることが考えられます。
