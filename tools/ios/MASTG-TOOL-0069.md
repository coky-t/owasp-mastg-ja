---
title: Usbmuxd
platform: ios
source: https://github.com/libimobiledevice/usbmuxd
---

usbmuxd は USB iPhone 接続を監視するソケットデーモンです。これを使用して、モバイルデバイスのローカルホストリスニングソケットをホストコンピュータの TCP ポートにマップできます。これにより、実際のネットワーク接続をセットアップすることなく、iOS デバイスに簡単に SSH 接続できます。usbmuxd は、通常モードで動作している iPhone を検出すると、スマホに接続して `/var/run/usbmuxd` 経由で受信したリクエストの中継を開始します。
