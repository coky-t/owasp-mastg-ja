---
masvs_category: MASVS-NETWORK
platform: android
title: 証明書ピン留め (Certificate Pinning)
---

[証明書ピン留め](../../../Document/0x04f-Testing-Network-Communication.md/#restricting-trust-identity-pinning) を Android アプリで使用すると、アプリが特定のアイデンティティを持つリモートエンドポイントのみと通信するようにして、中間マシン (Machine-in-the-Middle, MITM) 攻撃から保護できます。

正しく実装されていれば効果的ですが、安全でない実装は攻撃者がすべての通信を読み取ったり変更できる可能性があります。ピン留めの一般的な詳細については、[安全でないアイデンティティのピン留め (Insecure Identity Pinning)](https://github.com/coky-t/owasp-maswe-ja/blob/main/Document/weaknesses/MASVS-NETWORK/MASWE-0047.md) を参照してください。

アプリの API レベルと使用するライブラリに応じて、証明書ピン留めにはいくつかのアプローチがあります。以下では、最も一般的な方法を紹介します。具体的な実装の詳細については、["Deep Dive into Certificate Pinning on Android"](https://securevale.blog/articles/deep-dive-into-certificate-pinning-on-android/) を参照してください。

**重要な考慮事項:**

証明書ピン留めは **堅牢化策** ですが、万全ではありません。以下のように、攻撃者がこれを回避できる方法は複数あります。

- アプリの `TrustManager` の **証明書バリデーションロジックを変更します**。
- リソースディレクトリ (`res/raw/`, `assets/`) に保存されている **ピン留めされた証明書を置き換えます**。
- Network Security Configuration で **ピンを改変または削除します**。

このような変更を行うと **APK 署名が無効になり**、攻撃者は **APK を再パッケージ化して再署名する** 必要があります。これらのリスクを軽減するには、完全性チェック、ランタイム検証、難読化などの追加の保護が必要になることがあります。具体的な技法の詳細については、[証明書ピン留めのバイパス (Bypassing Certificate Pinning)](../../../techniques/android/MASTG-TECH-0012.md) を参照してください。

## Network Security Configuration によるピン留め (API 24 以降)

**Network Security Configuration (NSC)** は、コードの変更を必要とせずに宣言型で保守可能かつ安全なアプローチを提供するため、Android で証明書ピン留めを実装するための望ましく推奨される方法です。これは、`HttpsURLConnection` ベースの接続や `WebView` リクエストなど (カスタム `TrustManager` を使用されない限り)、アプリ内で Android フレームワークによって管理されるすべてのネットワークトラフィックに適用します。ネイティブコードからの通信の場合、NSC は適用されないため、他のメカニズムを検討する必要があります。

リモートエンドポイントへの接続を確立しようとする際、システムは以下を行います。

- 受信した証明書を取得して検証します。
- 公開鍵を抽出します。
- 抽出した公開鍵からダイジェストを計算します。
- ダイジェストをローカルピンのセットと比較します。

ピン留めされたダイジェストのうち少なくとも一つと一致すれば、証明書チェーンが有効であるとみなし、接続を続行します。

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config>
        <!-- Use certificate pinning for OWASP website access including sub domains -->
        <domain includeSubdomains="true">owasp.org</domain>
        <pin-set expiration="2028-12-31">
            <!-- Hash of the public key (SubjectPublicKeyInfo of the X.509 certificate) of
            the Intermediate CA of the OWASP website server certificate -->
            <pin digest="SHA-256">YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=</pin>
            <!-- Hash of the public key (SubjectPublicKeyInfo of the X.509 certificate) of
            the Root CA of the OWASP website server certificate -->
            <pin digest="SHA-256">Vjs8r4z+80wjNcr1YKepWQboSIRi63WsWXhIMN+eWys=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

**重要な考慮事項:**

- **バックアップピン:** プライマリ証明書が予期せず変更された場合に接続を維持するために、常にバックアップピンを含めます。
- **有効期限:** 適切な [有効期限](https://developer.android.com/privacy-and-security/security-config#CertificatePinning) を設定し、有効期限が過ぎた後にアプリがピン留めをバイパスしないように、タイムリーに更新します。
- **適用範囲:** この構成は `HttpsURLConnection` またはそれに依存するライブラリを使用して行われた接続のみに適用されることに注意します。他のネットワークライブラリやフレームワークでは個別のピン留め実装が必要になる可能性があります。

## カスタム TrustManager を使用したピン留め

Network Security Configuration が利用可能になる前は、証明書ピン留めを実装するための推奨方法は、カスタムの `TrustManager` を (`javax.net.ssl` API を使用して) 作成し、デフォルトの証明書バリデーションをオーバーライドすることでした。柔軟性のためや、より直接的な制御を必要とする場合、このアプローチを最新の Android バージョンでも使用できます。

このアプローチには以下の作業を含みます。

1. サーバーの証明書を `KeyStore` にロードします。
2. `KeyStore` 内の証明書のみを信頼するカスタム `TrustManager` を作成します。
3. `SSLContext` をカスタム `TrustManager` で初期化します。
4. カスタム `SSLContext` をネットワーク接続 (`HttpsURLConnection` など) のソケットファクトリとして適用します。

**重要な注意:** これは **低レベルのアプローチ** であり、慎重に行わないと **エラーが発生しやすくなります**。いくつかの重要な考慮事項は以下のとおりです。

- [`SSLSocket` はホスト名を自動的に検証しない](https://developer.android.com/privacy-and-security/security-ssl#WarningsSslSocket) ため、安全な実装の `HostnameVerifier` を使用して手動でこれを処理しなければなりません (これには `HostnameVerifier.verify()` の戻り値の明示的なチェックを含みます)。詳細については [Android ドキュメント](https://developer.android.com/privacy-and-security/risks/unsafe-hostname) を参照してください。
- すべての証明書を暗黙的に受け入れる ["trust-all" `TrustManager` を含めては**いけません**](https://developer.android.com/privacy-and-security/security-ssl#UnknownCa)。これは攻撃者が最小限の労力でユーザーデータを傍受して変更できるようになります。

## サードパーティライブラリを使用したピン留め

いくつかのサードパーティライブラリは証明書ピン留めをビルトインサポートを提供しており、場合によっては実装プロセスを簡素化します。これらのライブラリは一般的にカスタム `TrustManager` メソッドを利用して、より高レベルの抽象化と追加機能を提供します。注目すべき事例は以下のとおりです。

たとえば、[OkHttp](https://github.com/square/okhttp) は `CertificatePinner` でピン留めを提供しています。内部的には、カスタム `TrustManager` を使用して、ピン留めルールを適用します。

## WebView でのピン留め

Android のアプリ内 `WebView` トラフィックでは、最も簡単なアプローチは **Network Security Configuration** を利用することです。Android は同じアプリケーション内の WebView トラフィックに NSC ルールを自動的に適用するため、`network_security_config.xml` で設定したピン留めルールはその WebView にロードされるリソースにも適用されます。

NSC が提供する以上のさらなるカスタマイズを必要とする場合は、WebView レベルでリクエストを傍受することでピン留めを実装できます (例: `shouldInterceptRequest` と [カスタム `TrustManager`](#pinning-using-custom-trustmanagers) を使用する) が、ほとんどの場合、ビルトインサポートで十分であり、よりシンプルです。

## ネイティブコードのピン留め

[ネイティブコード](https://developer.android.com/ndk) (C/C++/Rust) でピン留めを実装することも可能です。コンパイルされたネイティブライブラリ (`.so` ファイル) 内に証明書を埋め込んだり動的に検証することで、一般的な APK リバースエンジニアリングによるピン留めチェックをバイパスしたり変更することを困難にすることができます。

ただし、このアプローチではネイティブ空間で証明書や公開鍵ハッシュを管理するための高度なセキュリティ専門知識と慎重な設計を必要とします。メンテナンスとデバッグも一般的により複雑になります。

## クロスプラットフォームフレームワークでのピン留め

Flutter, React Native, Cordova, Xamarin などのクロスプラットフォームフレームワークではネイティブアプリと同じネットワークスタックを使用しない可能性があるため、証明書ピン留めに関して特別な考慮事項を必要とすることがよくあります。たとえば、Flutter はプラットフォームのネットワークスタックではなく独自の Dart `HttpClient` (BoringSSL を使用) に依存しますが、Cordova は WebView で JavaScript を介してネットワークリクエストを行います。結果として、ピン留めの動作はさまざまです。一部のフレームワークではビルトインの構成オプションを提供し、別のものではサードパーティプラグインに依存し、あるものでは直接サポートは提供せず API 経由で手動で実装できます。フレームワークがネットワークを処理する方法を理解することが、適切なピン留めの適用を確保するために重要です。
