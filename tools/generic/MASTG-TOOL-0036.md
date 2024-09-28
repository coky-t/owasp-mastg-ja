---
title: r2frida
platform: generic
source: https://github.com/nowsecure/r2frida
---

[r2frida](https://github.com/nowsecure/r2frida "r2frida on Github") は、radare2 を Frida に接続できるプロジェクトであり、radare2 の強力なリバースエンジニアリング機能と Frida の動的計装ツールキットを効果的に融合しています。r2frida は Android と iOS の両方で使用でき、以下のことが可能です。

- USB または TCP 経由で、任意のローカルプロセスまたはリモート frida-server に radare2 をアタッチします。
- ターゲットプロセスからのメモリを読み書きします。
- マップ、シンボル、インポート、クラス、メソッドなどの Frida 情報を radare2 にロードします。
- Frida Javascript API に r2pipe インタフェースを公開して、Frida から r2 コマンドを呼び出します。

[r2frida の公式インストール手順](https://github.com/nowsecure/r2frida/blob/master/README.md#installation "r2frida installation instructions") を参照してください。

frida-server が実行中であれば、pid、spawn パス、ホストとポート、デバイス ID を使用してアタッチできるはずです。たとえば PID 1234 にアタッチするには以下のようにします。

```bash
r2 frida://1234
```

frida-server への接続方法のさまざまな例については、[r2frida の README ページの usage セクションを参照してください](https://github.com/nowsecure/r2frida/blob/master/README.md#usage "r2frida usage") 。

> 以下の例は Android アプリを使用して実行していますが、iOS アプリにも適用できます。

r2frida セッションに入ると、すべてのコマンドは `:` または `=!` で始まります。たとえば、radare2 ではバイナリ情報を表示するために `i` を実行しますが、r2frida では `:i` を使用します。

> `r2 frida://?` ですべてのオプションを表示します。

```bash
[0x00000000]> :i
arch                x86
bits                64
os                  linux
pid                 2218
uid                 1000
objc                false
runtime             V8
java                false
cylang              false
pageSize            4096
pointerSize         8
codeSigningPolicy   optional
isDebuggerAttached  false
```

メモリ内で特定のキーワードを検索するには、検索コマンド `:/` を使用します。

```bash
[0x00000000]> :/ unacceptable
Searching 12 bytes: 75 6e 61 63 63 65 70 74 61 62 6c 65
Searching 12 bytes in [0x0000561f05ebf000-0x0000561f05eca000]
...
Searching 12 bytes in [0xffffffffff600000-0xffffffffff601000]
hits: 23
0x561f072d89ee hit12_0 unacceptable policyunsupported md algorithmvar bad valuec
0x561f0732a91a hit12_1 unacceptableSearching 12 bytes: 75 6e 61 63 63 65 70 74 61
```

検索結果を JSON 形式で出力するには、前の検索コマンドに (r2 シェルで行うのと同様に) `j` を追加するだけです。これはほとんどのコマンドで使用できます。

```bash
[0x00000000]> :/j unacceptable
Searching 12 bytes: 75 6e 61 63 63 65 70 74 61 62 6c 65
Searching 12 bytes in [0x0000561f05ebf000-0x0000561f05eca000]
...
Searching 12 bytes in [0xffffffffff600000-0xffffffffff601000]
hits: 23
{"address":"0x561f072c4223","size":12,"flag":"hit14_1","content":"unacceptable \
policyunsupported md algorithmvar bad valuec0"},{"address":"0x561f072c4275", \
"size":12,"flag":"hit14_2","content":"unacceptableSearching 12 bytes: 75 6e 61 \
63 63 65 70 74 61"},{"address":"0x561f072c42c8","size":12,"flag":"hit14_3", \
"content":"unacceptableSearching 12 bytes: 75 6e 61 63 63 65 70 74 61 "},
...
```

ロードされたライブラリをリストするには、コマンド `:il` を使用し、コマンド `~` で radare2 内部の grep を使用して結果をフィルタします。たとえば、以下のコマンドは `keystore`、`ssl`、`crypto` というキーワードにマッチするロードされたライブラリをリストします。

```bash
[0x00000000]> :il~keystore,ssl,crypto
0x00007f3357b8e000 libssl.so.1.1
0x00007f3357716000 libcrypto.so.1.1
```

同様に、エクスポートをリストし、特定のキーワードで結果をフィルタするには、以下のようにします。

```bash
[0x00000000]> :iE libssl.so.1.1~CIPHER
0x7f3357bb7ef0 f SSL_CIPHER_get_bits
0x7f3357bb8260 f SSL_CIPHER_find
0x7f3357bb82c0 f SSL_CIPHER_get_digest_nid
0x7f3357bb8380 f SSL_CIPHER_is_aead
0x7f3357bb8270 f SSL_CIPHER_get_cipher_nid
0x7f3357bb7ed0 f SSL_CIPHER_get_name
0x7f3357bb8340 f SSL_CIPHER_get_auth_nid
0x7f3357bb7930 f SSL_CIPHER_description
0x7f3357bb8300 f SSL_CIPHER_get_kx_nid
0x7f3357bb7ea0 f SSL_CIPHER_get_version
0x7f3357bb7f10 f SSL_CIPHER_get_id
```

ブレークポイントをリストまたは設定するには、コマンド db を使用します。これはメモリを解析/変更する際に便利です。

```bash
[0x00000000]> :db
```

最後に、`:.` にスクリプト名を加えることで、Frida JavaScript コードを実行できることも覚えておいてください。

```bash
[0x00000000]> :. agent.js
```

Wiki プロジェクトの [r2frida の使い方](https://github.com/enovella/r2frida-wiki "Using r2frida") に多くの例があります。
