---
title: Keychain-Dumper
platform: ios
source: https://github.com/mechanico/Keychain-Dumper
---

[Keychain-dumper](https://github.com/mechanico/Keychain-Dumper "keychain-dumper") は、iOS デバイスが脱獄された後に、攻撃者が利用できるキーチェーンアイテムをチェックする iOS ツールです。このツールを入手する最も簡単な方法は、GitHub リポジトリからバイナリをダウンロードして、デバイスから実行することです。

```bash
$ git clone https://github.com/ptoomey3/Keychain-Dumper
$ scp -P 2222 Keychain-Dumper/keychain_dumper root@localhost:/tmp/
$ ssh -p 2222 root@localhost
iPhone:~ root# chmod +x /tmp/keychain_dumper
iPhone:~ root# /tmp/keychain_dumper
```

使用方法については [Keychain-dumper](https://github.com/mechanico/Keychain-Dumper "keychain-dumper") GitHub ページを参照してください。
