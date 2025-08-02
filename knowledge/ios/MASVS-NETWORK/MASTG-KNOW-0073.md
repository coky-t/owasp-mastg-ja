---
masvs_category: MASVS-NETWORK
platform: ios
title: iOS ネットワーク API (iOS Network APIs)
---

iOS 12.0 以降、[Network](https://developer.apple.com/documentation/network) フレームワークと [`URLSession`](https://developer.apple.com/documentation/foundation/urlsession) クラスはネットワークおよび URL リクエストを非同期および同期でロードするメソッドを提供します。古いバージョンの iOS では [Sockets API](https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/NetworkingTopics/Articles/UsingSocketsandSocketStreams.html) を利用できます。

## Network フレームワーク

`Network` フレームワークは 2018 年の [Apple Worldwide Developers Conference (WWDC)](https://developer.apple.com/videos/play/wwdc2018/715 "Introducing Network.framework: A modern alternative to Sockets") で紹介された、 Sockets API に代わるものです。この低レベルネットワークフレームワークは動的ネットワーク、セキュリティ、パフォーマンスのサポートが組み込まれたデータ送受信のためのクラスを提供します。

`Network` フレームワークでは引数 `using: .tls` が使用されている場合、デフォルトで TLS 1.3 が有効になっています。これは従来の [Secure Transport](https://developer.apple.com/documentation/security/secure_transport "API Reference Secure Transport") フレームワークよりも優先されるオプションです。

## URLSession

`URLSession` は `Network` フレームワーク上に構築されており、同じトランスポートサービスを利用します。また、エンドポイントが HTTPS の場合、このクラスはデフォルトで TLS 1.3 を使用します。

**HTTP および HTTPS の接続には `Network` フレームワークを直接利用するのではなく `URLSession` を使用すべきです。** `URLSession` クラスは両方の URL スキームをネイティブにサポートし、そのような接続のために最適化されています。定型コードをあまり必要としないため、エラーの可能性を減らし、デフォルトでセキュアな接続を確保できます。 `Network` フレームワークは低レベルや高度なネットワーク要件がある場合にのみ使用すべきです。

Apple の公式ドキュメントには `Network` フレームワークを使用して [netcat を実装する](https://developer.apple.com/documentation/network/implementing_netcat_with_network_framework "Implementing netcat with Network Framework") 例や、`URLSession` で [ウェブサイトのデータをメモリに取り込む](https://developer.apple.com/documentation/foundation/url_loading_system/fetching_website_data_into_memory "Fetching Website Data into Memory") 例が掲載されています。
