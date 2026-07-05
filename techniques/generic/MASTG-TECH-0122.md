---
title: 受動的な盗聴 (Passive Eavesdropping)
platform: generic
---

# MASTG-TECH-0122 受動的な盗聴 (Passive Eavesdropping)

この手法は [Wireshark](../../tools/network/MASTG-TOOL-0081.md), [tcpdump](../../tools/network/MASTG-TOOL-0080.md), [tcpdump (Android)](../../tools/network/MASTG-TOOL-0075.md) などのツールを使用してネットワークトラフィックを受動的にキャプチャするものです。ネットワークエンドポイントの特定、プロトコルメタデータの解析、アプリとサーバー間の通信方法の理解に役立ちます。しかし、TLS で暗号化された通信を自動的に復号化できません。とはいえ、[プリマスターシークレットを取得](https://wiki.wireshark.org/TLS#using-the-pre-master-secret) できれば、[TLS 復号化は可能です](https://wiki.wireshark.org/TLS#tls-decryption)。Android に特化した例については、[こちらの記事](https://nibarius.github.io/learning-frida/2022/05/21/sniffing-tls-traffic) を参照してください。

### いつ役立つのか？

受動的な盗聴は以下のシナリオで特に役立ちます。

* **アクティブな MITM のトラブルシューティング**: アクティブな傍受技法が失敗する原因となる可能性がある、TLS ハンドシェイクエラー、証明書バリデーションの失敗、ルーティング異常を特定します。
* **プレーンテキスト非 HTTP トラフィックの解析**: アプリが使用する XMPP, MQTT, DNS, SMB, カスタム UDP/TCP プロトコルなどのプロトコルを監視します。Android の Google Cloud Messaging (GCM) / Firebase Cloud Messaging (FCM) や iOS の Apple Push Notification Service (APNS) などのサービスからのプッシュ通知トラフィックの解析にも役立ちます。
* **プロキシ非対応アプリからのトラフィックの解析**: 一部のモバイルアプリはシステムプロキシ設定を無視したり、傍受プロキシを積極的に検出してブロックします。
* **ネットワーク異常と意図しないデータ漏洩の調査**: 受動的な監視は、予期しないサードパーティ通信、DNS リクエストによるデータ漏洩、異常な送信接続の検出に役立ちます。さらに、TLS 暗号化が直接ペイロード検査を妨げる場合でも、メタデータ漏洩 (リクエストサイズ、タイミングパターン、ドメイン名、パケットシーケンスなど) は貴重な洞察を提供し、サイドチャネル攻撃に役立つ可能性をあります。

### どのように機能するか？

受動的な盗聴は以下の二つの方法で行うことができます。

1. **ルート化済み Android または脱獄済み iOS デバイスで直接的に** デバイスがルート化 (Android) または脱獄済み (iOS) であれば、ホストコンピュータを必要とせずに、`tcpdump` または同様のツールを使用してネットワークトラフィックを直接的にキャプチャできます。これは送受信するすべてのパケットをリアルタイムで監視できます。
2. **ホストコンピュータ経由でトラフィックをルーティングすることによって (ルート化済み/脱獄済みと非ルート化/非脱獄済みの両方のデバイスで機能する)** デバイス上で直接パケットキャプチャが不可能または望ましくない場合には、ネットワークトラフィックをホストコンピュータにルートし、[Wireshark](../../tools/network/MASTG-TOOL-0081.md) や [tcpdump (Android)](../../tools/network/MASTG-TOOL-0075.md) などのツールを使用して解析できます。この手法は **ルート化済み/脱獄済みと非ルート化/非脱獄済みの両方のデバイス** に適用して、一般的に以下を通じて実現します。
   * **傍受プロキシを使用** して、HTTP/S トラフィックを傍受して解析します。
   * **VPN ベースのキャプチャを設定** して、制御されたネットワークトラフィックを通じてトラフィックをリダイレクトします。
   * Wi-Fi ネットワークで **ARP スプーフィングを実行するか、透過型ネットワークタップを設定** します。

### プラットフォームごとの手順

* **Android:** [基本的なネットワークモニタリング/スニッフィング (Basic Network Monitoring/Sniffing)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/android/MASTG-TECH-0010.md)
* **iOS:** [基本的なネットワークモニタリング/スニッフィング (Basic Network Monitoring/Sniffing)](../ios/MASTG-TECH-0062.md)
