---
title: アプリケーション層でネットワーク API をフックして HTTP トラフィックを傍受する (Intercepting HTTP Traffic by Hooking Network APIs at the Application Layer)
platform: generic
---

アプリをテストする目的によっては、トラフィックがネットワーク層に到達する前に、またはレスポンスがアプリで受信された際に、トラフィックを監視するだけで十分なことがよくあります。

つまり、特定の機密データがネットワークに送信されているかどうかを確認したいだけであれば、本格的な MITM 攻撃 (ARP スプーフィング攻撃など) をデプロイする必要はないことを意味します。このアプローチでは、TLS 検証やピン留めに干渉することはありません。

[Frida を代替手段として](https://gaiaslastlaugh.medium.com/frida-as-an-alternative-to-network-tracing-5173cfbd7a0b) 使用できます。

この技法は以下のような場合にも役立ちます。

- カスタムネットワークスタックを使用するアプリのトラフィックを傍受する。
- Flutter などの特定のクロスプラットフォームフレームワークで構築されたアプリのトラフィックを傍受する。
    - Android: [Flutter HTTPS トラフィックの傍受 (Intercepting Flutter HTTPS Traffic)](../../techniques/android/MASTG-TECH-0109.md)
    - iOS: [Flutter HTTPS トラフィックの傍受 (Intercepting Flutter HTTPS Traffic)](../../techniques/ios/MASTG-TECH-0110.md)
- BLE, NFC など、MITM 攻撃のデプロイに多大なコストと複雑性を伴う可能性のある、その他の種類のトラフィックを傍受する。
- MQTT や CoAP など、より特殊な傍受技法を必要とする可能性のある、プロトコルを解析する。
- 独自の傍受戦略が必要になることもある、WebSocket トラフィックを監視する。

たとえば、OpenSSL の `SSL_write` や `SSL_read` などの適切な関数をフックする必要があるだけです。

これは標準 API ライブラリ関数とクラスを使用するアプリでは非常にうまく機能しますが、以下のようないくつかの欠点があるかもしれません。

- アプリはカスタムネットワークスタックを実装しているかもしれず、使用できる API を見つけるにはアプリの解析に時間をかける必要があるでしょう。[このブログ記事](https://hackmag.com/security/ssl-sniffing/ "Searching for OpenSSL traces with signature analysis") の "Searching for OpenSSL traces with signature analysis" セクションを参照してください。
- (多数のメソッドコールと実行スレッドにまたがる) HTTP レスポンスペアを再構成するための適切なフックスクリプトを作成するのは非常に時間がかかるかもしれません。[規制のスクリプト](https://github.com/fanxs-t/Android-SSL_read-write-Hook/blob/master/frida-hook.py) や [代替ネットワークスタック](https://codeshare.frida.re/@owen800q/okhttp3-interceptor/) 用のスクリプトが見つかるかもしれませんが、アプリやプラットフォームによっては、これらのスクリプトには多くのメンテナンスが必要になるかもしれませんし、_必ず動作する_ とは限りません。

いくつかの例をご覧ください。

- ["Universal interception. How to bypass SSL Pinning and monitor traffic of any application"](https://hackmag.com/security/ssl-sniffing/), sections "Grabbing payload prior to transmission" and "Grabbing payload prior to encryption"
- ["Frida as an Alternative to Network Tracing"](https://gaiaslastlaugh.medium.com/frida-as-an-alternative-to-network-tracing-5173cfbd7a0b)
