---
title: mitmproxy
platform: network
source: https://github.com/mitmproxy/mitmproxy/
---

[mitmproxy](https://mitmproxy.org/ "mitmproxy") はフリーでオープンソースの対話型 HTTPS 傍受プロキシです。

- **コマンドライン**: `mitmdump` は mitmproxy のコマンドラインバージョンです。HTTP 用の tcpdump と考えてください。HTTP/1、HTTP/2、WebSocket、その他の SSL/TLS で保護されたプロトコルなどのウェブトラフィックを傍受、検査、変更、再生するために使用できます。HTML から Protobuf まで、さまざまなメッセージタイプを整形およびデコードし、特定のメッセージをオンザフライで傍受し、宛先に到達する前に変更し、後からクライアントやサーバーに再生できます。
- **ウェブインタフェース**: `mitmweb` は mitmproxy のウェブベースのインタフェースです。Chrome の DevTools と同様のエクスペリエンスに加え、リクエストの傍受や再生などの追加機能もあります。
- **Python API**: 強力なアドオンを作成し、mitmdump で mitmproxy をスクリプト化します。スクリプト API は mitmproxy の完全な制御を提供し、メッセージを自動的に変更したり、トラフィックをリダイレクトしたり、メッセージを可視化したり、カスタムコマンドを実装することを可能にします。

## インストール

```bash
brew install mitmproxy
```

インストール手順は [こちら](https://docs.mitmproxy.org/stable/overview-installation) です。

## 使い方

ドキュメントは [こちら](https://docs.mitmproxy.org/stable/) です。mitmproxy はデフォルトでは通常の HTTP プロキシとして起動し、`http://localhost:8080` でリッスンします。すべてのトラフィックを mitmproxy 経由でルーティングするように、ブラウザやデバイスを設定する必要があります。たとえば、Android エミュレータでは [こちら](https://docs.mitmproxy.org/stable/howto-install-system-trusted-ca-android/) に示されている手順に従う必要があります。

たとえば、すべてのトラフィックをファイルにキャプチャするには以下のようにします。

```bash
mitmdump -w outfile
```

こちらは、すべてのレスポンスに新しいヘッダを追加するだけの、add_header.py スクリプトで mitmproxy を実行します。

```bash
mitmdump -s add_header.py
```
