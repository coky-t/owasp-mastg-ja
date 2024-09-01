---
title: disable-flutter-tls-verification
platform: generic
source: https://github.com/NVISOsecurity/disable-flutter-tls-verification
---

[disable-flutter-tls-verification](https://github.com/NVISOsecurity/disable-flutter-tls-verification) は Flutter の TLS 検証を無効化する Frida スクリプトであり、Android (ARM32, ARM64, x64) および iOS (ARM64) で動作します。パターンマッチングを使用して [handshake.cc 内の ssl_verify_peer_cert](https://github.com/google/boringssl/blob/master/ssl/handshake.cc#L323) を検索します。詳細については [このブログ投稿](https://blog.nviso.eu/2022/08/18/intercept-flutter-traffic-on-ios-and-android-http-https-dio-pinning/) をご覧ください。

Frida CodeShare 経由、またはこれらの [手順](https://github.com/NVISOsecurity/disable-flutter-tls-verification) で示されているように disable-flutter-tls.js をリポジトリからダウンロードして使用できます。
