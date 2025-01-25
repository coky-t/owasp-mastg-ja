---
title: オープンコネクションの取得 (Get Open Connections)
platform: ios
---

`lsof` コマンドを `-i` オプション付きで実行すると、デバイス上でのすべてのアクティブなプロセスに対するオープンなネットワークポートのリストを取得します。特定のプロセスに対するオープンなネットワークポートのリストを取得するには、`lsof -i -a -p <pid>` コマンドを使用できます。`-a` (AND) オプションはフィルタリングに使用されます。以下に PID 1 に対するフィルタされた出力を示します。

```bash
iPhone:~ root# lsof -i -a -p 1
COMMAND PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
launchd   1 root   27u  IPv6 0x69c2ce210efdc023      0t0  TCP *:ssh (LISTEN)
launchd   1 root   28u  IPv6 0x69c2ce210efdc023      0t0  TCP *:ssh (LISTEN)
launchd   1 root   29u  IPv4 0x69c2ce210eeaef53      0t0  TCP *:ssh (LISTEN)
launchd   1 root   30u  IPv4 0x69c2ce210eeaef53      0t0  TCP *:ssh (LISTEN)
launchd   1 root   31u  IPv4 0x69c2ce211253b90b      0t0  TCP 192.168.1.12:ssh->192.168.1.8:62684 (ESTABLISHED)
launchd   1 root   42u  IPv4 0x69c2ce211253b90b      0t0  TCP 192.168.1.12:ssh->192.168.1.8:62684 (ESTABLISHED)
```
