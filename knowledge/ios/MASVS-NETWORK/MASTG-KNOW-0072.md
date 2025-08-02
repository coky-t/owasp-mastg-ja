---
masvs_category: MASVS-NETWORK
platform: ios
title: サーバー信頼性評価 (Server Trust Evaluation)
---

ATS は Transport Layer Security (TLS) プロトコルで規定されたデフォルトのサーバー信頼性評価を補完する拡張セキュリティチェックを課します。ATS 制限を緩めているとアプリのセキュリティが低下します。アプリは ATS 例外を追加する前に、サーバーセキュリティを向上させる別の方法を優先させるべきです。

[Apple Developer ドキュメント](https://developer.apple.com/documentation/security/preventing_insecure_network_connections) ではアプリは `URLSession` を使用してサーバー信頼性評価を自動的に処理できると説明しています。しかし、アプリはそのプロセスをカスタマイズすることもできます。たとえば、以下のことができます。

- 証明書の有効期限をバイパスまたはカスタマイズする。
- 信頼性を緩める/広げる: システムによって拒否されるようなサーバー資格情報を受け入れる。たとえば、アプリに埋め込まれた自己署名証明書を使用して開発サーバーにセキュア接続を行う。
- 信頼性を強める: システムによって受け入れられるサーバー資格証明を拒否します。
- その他

<img src="../../../Document/Images/Chapters/0x06g/manual-server-trust-evaluation.png" width="100%" />

参考情報:

- [Preventing Insecure Network Connections](https://developer.apple.com/documentation/security/preventing_insecure_network_connections)
- [Performing Manual Server Trust Authentication](https://developer.apple.com/documentation/foundation/url_loading_system/handling_an_authentication_challenge/performing_manual_server_trust_authentication)
- [Certificate, Key, and Trust Services](https://developer.apple.com/documentation/security/certificate_key_and_trust_services)
