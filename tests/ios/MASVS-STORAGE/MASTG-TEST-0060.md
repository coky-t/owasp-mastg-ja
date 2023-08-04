---
masvs_v1_id:
- MSTG-STORAGE-10
masvs_v2_id:
- MASVS-STORAGE-2
platform: ios
title: 機密データに対してのメモリのテスト (Testing Memory for Sensitive Data)
masvs_v1_levels:
- L2
---

## 概要

## 静的解析

メモリを介して公開される機密データについて静的解析を実行する際には、以下のことを行う必要があります。

- アプリケーションコンポーネントを特定し、データが使用される場所をマップしてみます。
- 機密データはできるだけ少ないコンポーネントで処理されることを確認します。
- 機密データを含むオブジェクトが必要なくなったらオブジェクト参照が適切に削除されることを確認します。
- 機密性の高いデータが必要なくなったらすぐに上書きされることを確認します。
- `String` や `NSString` などのイミュータブルなデータ型を介してそのようなデータを渡さないこと。
- 非プリミティブなデータ型を避けること (データが残る可能性があるため) 。
- 参照を削除する前にメモリ内の値を上書きすること。
- サードパーティコンポーネント (ライブラリやフレームワーク) に注意を払うこと。上記の推奨事項に従ってデータを処理するパブリック API があれば、開発者がここで説明した問題を考慮したことを示す良い指標となります。

## 動的解析

iOS アプリのメモリに機密データがないか動的にテストするためのアプローチやツールはいくつかあります。

### メモリダンプの取得と解析

脱獄済みデバイスを使用しているか、脱獄していないデバイスを使用しているかに関係なく、[objection](https://github.com/sensepost/objection "Objection") や [Fridump](https://github.com/Nightbringer21/fridump "Fridump") でアプリのプロセスメモリをダンプできます。このプロセスの詳しい説明は "iOS の改竄とリバースエンジニアリング" の章の "[メモリダンプ](../../../Document/0x06c-Reverse-Engineering-and-Tampering.md#memory-dump "Memory Dump")" のセクションにあります。

メモリを (たとえば "memory" というファイルに) ダンプした後、探しているデータの性質に応じて、そのメモリダンプを処理して解析するための一連のさまざまなツールが必要になります。たとえば、文字列に注目しているのであれば、`strings` や `rabin2 -zz` コマンドを実行して文字列を抽出するだけで十分かもしれません。

```bash
# using strings
$ strings memory > strings.txt

# using rabin2
$ rabin2 -ZZ memory > strings.txt
```

お気に入りのエディタで `strings.txt` を開き、内容を調べて機密情報を特定します。

しかし、他の種類のデータを調べたいのであれば、radare2 とその検索機能を使用するとよいでしょう。詳細とオプション一覧については radare2 の検索コマンド (`/?`) のヘルプを参照してください。以下にその一部を示しています。

```bash
$ r2 <name_of_your_dump_file>

[0x00000000]> /?
Usage: /[!bf] [arg]  Search stuff (see 'e??search' for options)
|Use io.va for searching in non virtual addressing spaces
| / foo\x00                    search for string 'foo\0'
| /c[ar]                       search for crypto materials
| /e /E.F/i                    match regular expression
| /i foo                       search for string 'foo' ignoring case
| /m[?][ebm] magicfile         search for magic, filesystems or binary headers
| /v[1248] value               look for an `cfg.bigendian` 32bit value
| /w foo                       search for wide string 'f\0o\0o\0'
| /x ff0033                    search for hex string
| /z min max                   search for strings of given size
...
```

### ランタイムメモリ解析

[r2frida](../../../Document/0x08a-Testing-Tools.md#r2frida) を使用すると、実行時にアプリのメモリをダンプすることなく解析して調査できます。たとえば、r2frida から前述の検索コマンドを実行して、文字列や16進値などについてメモリを検索できます。その際、`r2 frida://usb//<name_of_your_app>` でセッションを開始した後、検索コマンド (および他の r2frida 固有のコマンド) の前にバックスラッシュ `\` を付けることを忘れないでください。

詳細情報、オプション、アプローチについては、"iOS の改竄とリバースエンジニアリング" の章の "[メモリ内検索](../../../Document/0x06c-Reverse-Engineering-and-Tampering.md#in-memory-search "In-Memory Search")" セクションを参照してください。
