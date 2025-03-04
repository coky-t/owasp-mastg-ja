---
title: bettercap
platform: network
source: https://github.com/bettercap/bettercap
---

セキュリティ研究者やリバースエンジニアに、Wi-Fi、Bluetooth Low Energy、ワイヤレス HID ハイジャッキング、Ethernet ネットワーク偵察用の使いやすいオールインワンソリューションを提供することを目的とした強力なフレームワークです。ネットワークペネトレーションテスト時に [中間マシン (Machine-in-the-Middle, MITM)](../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) 攻撃をシミュレートするために使用できます。これは [ARP ポイズニングまたはスプーフィング](https://en.wikipedia.org/wiki/ARP_spoofing "ARP poisoning/spoofing") をターゲットコンピュータに実行することで実現します。そのような攻撃が成功すると、二つのコンピュータ間のすべてのパケットが、MITM として機能して解析のためにトラフィックを傍受できる第三のコンピュータにリダイレクトされます。

> bettercap は MITM 攻撃を実行するための強力なツールであり、現在では ettercap の代わりに推奨されています。bettercap のサイトの [Why another MITM tool?](https://www.bettercap.org/legacy/#why-another-mitm-tool "Why another MITM tool?") も参照してください。

bettercap はすべての主要な Linux および Unix オペレーティングシステムで利用可能であり、それぞれのパッケージインストールメカニズムの一部になっているはずです。MITM として動作するホストコンピュータにインストールする必要があります。macOS では brew を使用してインストールできます。

```bash
brew install bettercap
```

Kali Linux では `apt-get` で bettercap をインストールできます。

```bash
apt-get update
apt-get install bettercap
```

[LinuxHint](https://linuxhint.com/install-bettercap-on-ubuntu-18-04-and-use-the-events-stream/ "Install Bettercap on Ubuntu 18.04") には、Ubuntu Linux 18.04 向けのインストール手順もあります。
