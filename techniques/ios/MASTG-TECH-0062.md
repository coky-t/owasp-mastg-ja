---
title: 基本的なネットワークモニタリング/スニッフィング (Basic Network Monitoring/Sniffing)
platform: ios
---

iOS デバイス用に [Remote Virtual Interface を作成すること](https://stackoverflow.com/questions/9555403/capturing-mobile-phone-traffic-on-wireshark/33175819#33175819 "Wireshark + OSX + iOS") で、iOS 上のすべてのトラフィックをリアルタイムでリモートから傍受できます。まず、macOS ホストコンピュータに [Wireshark](../../tools/network/MASTG-TOOL-0081.md) がインストールされていることを確認します。

1. iOS デバイスを USB 経由で macOS ホストコンピュータに接続します。
2. スニッフィングを開始する前に、iOS デバイスの UDID を知る必要があります。UDID を取得するには ["iOS デバイスの UDID を取得する"](../../Document/0x06b-iOS-Security-Testing.md#obtaining-the-udid-of-an-ios-device) セクションをチェックしてください。macOS で Terminal を開き、UDID を iOS デバイスの UDID に置き換えて以下のコマンドを実行します。

```bash
$ rvictl -s <UDID>
Starting device <UDID> [SUCCEEDED] with interface rvi0
```

1. Wireshark を起動し、キャプチャインタフェースとして "rvi0" を選択します。
2. Wireshark の Capture Filters でトラフィックをフィルタし、監視したいものを表示します (たとえば、IP アドレス 192.168.1.1 経由で送受信されるすべての HTTP トラフィック)。

```default
ip.addr == 192.168.1.1 && http
```

<img src="../../Document/Images/Chapters/0x06b/wireshark_filters.png" width="100%" />

Wireshark のドキュメントでは [Capture Filters](https://wiki.wireshark.org/CaptureFilters "Capture Filters") の例を多数提供しており、トラフィックをフィルタして必要な情報を取得するのに役立つはずです。
