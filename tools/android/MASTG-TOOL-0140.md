---
title: frida-multiple-unpinning
platform: android
source: https://codeshare.frida.re/@akabe1/frida-multiple-unpinning
---

frida-multiple-unpinning はさまざまな形式の TLS ピン留めをバイパスするための Frida CodeShare スクリプトです。これは CodeShare で利用可能な最も包括的な TLS ピン留めバイパススクリプトの一つです。その主な強みは動的バイパスであり、`SSLPeerUnverifiedException` クラスのインスタンス化を検出し、例外をスローするメソッドに自動的にパッチを適用します。

このスクリプトは Frida で直接実行できます。

```bash
$ frida -U --codeshare akabe1/frida-multiple-unpinning -f YOUR_BINARY
```
