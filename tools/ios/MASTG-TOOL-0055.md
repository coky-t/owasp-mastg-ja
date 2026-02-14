---
title: iproxy
platform: ios
hosts: [macOS, windows, linux]
source: https://github.com/libimobiledevice/libusbmuxd
---

iproxy は、接続された iOS デバイスからホストマシンのポートにポートを転送できます。脱獄によっては SSH ポートがパブリックインタフェースに公開されないため、脱獄済みデバイスとやり取りする際に役立ちます。`iproxy` では、SSH ポートを USB 経由でホストに転送できるため、依然としてホストに接続できます。

> [!WARNING]
> 
> 多くのパッケージリポジトリ (apt, brew, cargo など) に libimobiledevice ツールのバージョンがありますが、古くなっていることがよくあります。最良の結果を得るには、さまざまなツールをソースからコンパイルすることをお勧めします。
