---
title: ProxyDroid
platform: android
source: https://github.com/madeye/proxydroid/
---

ProxyDroid は [Google Play で入手可能](https://play.google.com/store/apps/details?id=org.proxydroid) なオープンソースアプリであり、デバイスが HTTP(S) トラフィックをプロキシに送信するように構成します。`iptables` を使用してトラフィックをプロキシに強制的に送るため、システムのプロキシ設定を無視するアプリに特に便利です。

`iptables` の使用のため、考慮すべき制限がいくつかあります。

- ProxyDroid はルート化済みデバイスでのみ動作します
- ポート 80, 443, 5228 のみが傍受されます
- プロキシは _透過プロキシ_ モードで構成する必要があります
