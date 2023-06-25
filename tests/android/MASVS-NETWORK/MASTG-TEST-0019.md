---
masvs_v1_id:
- MSTG-NETWORK-1
masvs_v2_id:
- MASVS-NETWORK-1
platform: android
title: ネットワーク上のデータ暗号化のテスト (Testing Data Encryption on the Network)
masvs_v1_levels:
- L1
- L2
---

## 概要

## 静的解析

### セキュアプロトコルでのネットワークリクエストのテスト

まず、ソースコード内のすべてのネットワークリクエストを特定し、プレーンな HTTP URL が使用されていないことを確認する必要があります。機密情報は [`HttpsURLConnection`](https://developer.android.com/reference/javax/net/ssl/HttpsURLConnection.html "HttpsURLConnection") または [`SSLSocket`](https://developer.android.com/reference/javax/net/ssl/SSLSocket.html "SSLSocket") (TLS を使用したソケットレベル通信用) を使用して、セキュアチャネル上で送信されていることを確認します。

### ネットワーク API 使用箇所のテスト

次に、セキュアな接続を行うはずである低レベル API (`SSLSocket` など) を使用している場合でも、セキュアな実装が必要であることに注意してください。たとえば、`SSLSocket` はホスト名を検証 **しません** 。ホスト名を検証するには `getDefaultHostnameVerifier` を使用します。Android 開発者ドキュメントに [コード例](https://developer.android.com/training/articles/security-ssl.html#WarningsSslSocket "Warnings About Using SSLSocket Directly") があります。

### クリアテキストトラフィックのテスト

次に、アプリがクリアテキスト HTTP トラフィックを許可していないことを確認する必要があります。Android 9 (API レベル 28) 以降、クリアテキスト HTTP トラフィックはデフォルトでブロックされます ([デフォルトの Network Security Configuration](../../../Document/0x05g-Testing-Network-Communication.md#default-configurations) のおかげで) が、アプリケーションがクリアテキストを送信できる方法はまだいくつかあります。

- AndroidManifest.xml ファイルの `<application>` タグの [`android:usesCleartextTraffic`](https://developer.android.com/guide/topics/manifest/application-element#usesCleartextTraffic "Android documentation - usesCleartextTraffic flag") 属性を設定します。なお Network Security Configuration を設定している場合、このフラグは無視されることに注意してください。
- Network Security Configuration を設定して、 `<domain-config>` 要素の `cleartextTrafficPermitted` 属性を true に設定することでクリアテキストトラフィックを有効にします。
- 低レベル API ([`Socket`](https://developer.android.com/reference/java/net/Socket "Socket class") など) を使用して、カスタム HTTP 接続をセットアップします。
- クロスプラットフォームフレームワーク (Flutter, Xamarin など) を使用します。これらは一般的に HTTP ライブラリ用の独自の実装を持っているためです。

上記のすべてのケースは全体として慎重に分析しなければなりません。たとえば、アプリが Android Manifest や Network Security Configuration でクリアテキストトラフィックを許可していなくても、実際にはまだ HTTP トラフィックを送信している可能性があります。低レベル API (Network Security Configuration が無視される) を使用している場合やクロスプラットフォームフレームワークが適切に設定されていない場合がそれにあたります。

詳細については記事 ["Security with HTTPS and SSL"](https://developer.android.com/training/articles/security-ssl.html) を参照してください。

## 動的解析

テスト対象アプリの送受信ネットワークトラフィックを傍受し、このトラフィックが暗号化されていることを確認します。以下のいずれかの方法でネットワークトラフィックを傍受できます。

- [OWASP ZAP](../../../Document/0x08a-Testing-Tools.md#owasp-zap) や [Burp Suite](../../../Document/0x08a-Testing-Tools.md#burp-suite) などの傍受プロキシですべての HTTP(S) と Websocket トラフィックをキャプチャし、すべてのリクエストが HTTP ではなく HTTPS を介して行われていることを確認します。
- Burp や OWASP ZAP などの傍受プロキシは HTTP(S) トラフィックのみを表示します。しかし、[Burp-non-HTTP-Extension](https://github.com/summitt/Burp-Non-HTTP-Extension "Burp-non-HTTP-Extension") などの Burp プラグインや [mitm-relay](https://github.com/jrmdev/mitm_relay "mitm-relay") というツールを使用して、XMPP やその他のプロトコルによる通信をデコードおよび可視化できます。

> アプリケーションによっては証明書ピン留めのため Burp や OWASP ZAP などのプロキシで動作しないことがあります。このようなシナリオでは、 ["カスタム証明書ストアおよび証明書ピン留めのテスト"](../../../tests/android/MASVS-NETWORK/MASTG-TEST-0022.md) をチェックしてください。

詳細については以下を参照してください。

- "モバイルアプリのネットワーク通信" の章の ["ネットワーク層でのトラフィックの傍受"](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-traffic-on-the-network-layer)
- "Android セキュリティテスト入門" の章の ["ネットワークテスト環境のセットアップ"](../../../Document/0x05b-Basic-Security_Testing.md#setting-up-a-network-testing-environment)
