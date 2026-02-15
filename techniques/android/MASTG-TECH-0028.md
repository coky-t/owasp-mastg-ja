---
title: オープンコネクションの取得 (Get Open Connections)
platform: android
---

システム全体のネットワーク情報は `/proc/net` または `/proc/<pid>/net` ディレクトリを調べることで見つかります (何らかの理由で、プロセス固有ではありません)。これらのディレクトリには複数のファイルが存在し、テスト担当者の観点からは `tcp`, `tcp6`, `udp` が関連していると考えられます。

```bash
# cat /proc/7254/net/tcp
sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
...
69: 1101A8C0:BB2F 9A447D4A:01BB 01 00000000:00000000 00:00000000 00000000 10093        0 75412 1 0000000000000000 20 3 19 10 -1
70: 1101A8C0:917C E3CB3AD8:01BB 01 00000000:00000000 00:00000000 00000000 10093        0 75553 1 0000000000000000 20 3 23 10 -1
71: 1101A8C0:C1E3 9C187D4A:01BB 01 00000000:00000000 00:00000000 00000000 10093        0 75458 1 0000000000000000 20 3 19 10 -1
...
```

上記の出力の中で、私たちに最も関連するフィールドは以下のとおりです。

- `rem_address`: リモートアドレスとポート番号のペア (16 進数表記)。
- `tx_queue` と `rx_queue`: カーネルメモリ使用の観点での送出データキューと受入データキュー。これらのフィールドはコネクションがどの程度アクティブに使用されているかの示唆を与えます。
- `uid`: ソケット作成者の実効 UID を含みます。

もう一つの選択肢は `netstat` コマンドを使用することです。これもシステム全体のネットワークアクティビティに関する情報をより読みやすい形式で提供し、要件に応じて簡単にフィルタできます。たとえば、PID で簡単にフィルタできます。

```bash
# netstat -p | grep 24685
Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program Name
tcp        0      0 192.168.1.17:47368      172.217.194.103:https   CLOSE_WAIT  24685/com.google.android.youtube
tcp        0      0 192.168.1.17:47233      172.217.194.94:https    CLOSE_WAIT  24685/com.google.android.youtube
tcp        0      0 192.168.1.17:38480      sc-in-f100.1e100.:https ESTABLISHED 24685/com.google.android.youtube
tcp        0      0 192.168.1.17:44833      74.125.24.91:https      ESTABLISHED 24685/com.google.android.youtube
tcp        0      0 192.168.1.17:38481      sc-in-f100.1e100.:https ESTABLISHED 24685/com.google.android.youtube
...
```

`netstat` の出力は `/proc/<pid>/net` を読むよりも明らかにユーザーフレンドリです。私たちに最も関連のあるフィールドは、前の出力と同様に、以下のとおりです。

- `Foreign Address`: リモートアドレスとポート番号のペア (ポート番号はポートに関連付けられたプロトコルの well-known 名で置き換え可能です)。
- `Recv-Q` と `Send-Q`: 受信キューと送信キューに関する統計。コネクションがどの程度アクティブに使用されているかを示します。
- `State`: ソケットの状態。たとえば、ソケットがアクティブに使用中 (`ESTABLISHED`) であるか、閉じられている (`CLOSED`) かです。
