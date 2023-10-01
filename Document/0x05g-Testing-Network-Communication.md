---
masvs_category: MASVS-NETWORK
platform: android
---

# Android のネットワーク通信

## 概要

ほとんどすべての Android アプリは一つ以上のリモートサービスのクライアントとして動作します。このネットワーク通信は一般的に公衆 Wi-Fi などの信頼できないネットワーク上で行われるため、従来のネットワークベースの攻撃が潜在的な問題になります。

最近のモバイルアプリの多くはさまざまな HTTP ベースのウェブサービスを使用しています。これらのプロトコルは十分に文書化されており、サポートされているからです。

### Android Network Security Configuration

Android 7.0 (API レベル 24) 以降、Android アプリはいわゆる [Network Security Configuration](https://developer.android.com/training/articles/security-config) 機能を使用して、ネットワークセキュリティ設定をカスタマイズできます。これは以下の主要な機能を提供します。

- **クリアテキストトラフィック**: クリアテキストトラフィックの偶発的な使用からアプリを保護します (またはそれを有効にします) 。
- **カスタムトラストアンカー**: アプリのセキュア接続のために信頼する認証局 (Certificate Authority, CA) をカスタマイズできます。たとえば、特定の自己署名証明書を信頼したり、アプリが信頼するパブリック CA のセットを制限します。
- **証明書ピンニング**: アプリのセキュア接続を特定の証明書に制限します。
- **デバッグのみのオーバーライド**: インストールベースへの追加リスクなしに、アプリのセキュア接続を安全にデバッグします。

アプリがカスタム Network Security Configuration を定義している場合、AndroidManifest.xml ファイルの `android:networkSecurityConfig` を探すことでその場所を取得できます。

```xml
<application android:networkSecurityConfig="@xml/network_security_config"
```

この場合、ファイルは `@xml` (/res/xml と同じ) にあり、名前は "network_security_config" (異なることがあります) です。 "res/xml/network_security_config.xml" として見つけることができるはずです。コンフィグレーションが存在する場合、 [システムログ](0x05b-Android-Security-Testing.md#monitoring-system-logs) に以下のイベントが表示されるはずです。

```bash
D/NetworkSecurityConfig: Using Network Security Config from resource network_security_config
```

Network Security Configuration は [XML ベース](https://developer.android.com/training/articles/security-config#FileFormat) で、アプリ全体とドメイン固有の設定を構成するために使用できます。

- `base-config` はアプリが確立しようとするすべての接続に適用されます。
- `domain-config` は特定のドメインに対して `base-config` をオーバーライドします (複数の `domain` エントリを含めることができます) 。

たとえば、以下のコンフィグレーションでは `base-config` を使用して、すべてのドメインに対してクリアテキストトラフィックを禁止しています。しかし `domain-config` を使用してそのルールをオーバーライドし、`localhost` に対するクリアテキストトラフィックを明示的に許可しています。

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
    <domain-config cleartextTrafficPermitted="true">
        <domain>localhost</domain>
    </domain-config>
</network-security-config>
```

さらに学ぶために:

- ["A Security Analyst’s Guide to Network Security Configuration in Android P"](https://www.nowsecure.com/blog/2018/08/15/a-security-analysts-guide-to-network-security-configuration-in-android-p/)
- [Android Developers - Network Security Configuration](https://developer.android.com/training/articles/security-config)
- [Android Codelab - Network Security Configuration](https://developer.android.com/codelabs/android-network-security-config)

#### デフォルトコンフィグレーション

Android 9 (API レベル 28) 以上を対象とするアプリのデフォルトコンフィグレーションは以下のとおりです。

```xml
<base-config cleartextTrafficPermitted="false">
    <trust-anchors>
        <certificates src="system" />
    </trust-anchors>
</base-config>
```

Android 7.0 (API レベル 24) から Android 8.1 (API レベル 27) を対象とするアプリのデフォルトコンフィグレーションは以下のとおりです。

```xml
<base-config cleartextTrafficPermitted="true">
    <trust-anchors>
        <certificates src="system" />
    </trust-anchors>
</base-config>
```

Android 6.0 (API レベル 23) 以下を対象とするアプリのデフォルトコンフィグレーションは以下のとおりです。

```xml
<base-config cleartextTrafficPermitted="true">
    <trust-anchors>
        <certificates src="system" />
        <certificates src="user" />
    </trust-anchors>
</base-config>
```

#### 証明書ピンニング

Network Security Configuration は特定のドメインに [宣言型証明書](https://developer.android.com/training/articles/security-config.html#CertificatePinning "Certificate Pinning using Network Security Configuration") をピン留めするためにも使用できます。対応する X.509 証明書の公開鍵 (`SubjectPublicKeyInfo`) のダイジェスト (ハッシュ) のセットを Network Security Configuration の `<pin-set>` で提供することによって行えます。

リモートエンドポイントへの接続を確立しようとする際、システムは以下を行います。

- 受信した証明書を取得して検証する。
- 公開鍵を抽出する。
- 抽出した公開鍵からダイジェストを計算する。
- ダイジェストをローカルピンのセットと比較する。

ピン留めされたダイジェストのうち少なくとも一つと一致すれば、証明書チェーンが有効であるとみなし、接続を続行します。

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config>
        Use certificate pinning for OWASP website access including sub domains
        <domain includeSubdomains="true">owasp.org</domain>
        <pin-set expiration="2018/8/10">
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

### セキュリティプロバイダ

Android は [セキュリティプロバイダ](https://developer.android.com/training/articles/security-gms-provider.html "Update your security provider to protect against SSL exploits") に依存して SSL/TLS ベースの接続を提供しています。この種のセキュリティプロバイダの問題 (一例では [OpenSSL](https://www.openssl.org/news/vulnerabilities.html "OpenSSL Vulnerabilities")) は、デバイスに付随するもので、多くの場合バグや脆弱性があります。

既知の脆弱性を回避するために、開発者はアプリケーションが適切なセキュリティプロバイダをインストールすることを確認する必要があります。
2016年7月11日以降、Google は脆弱なバージョンの OpenSSL を使用する [Play ストアのアプリケーション提出を拒否しています](https://support.google.com/faqs/answer/6376725?hl=en "How to address OpenSSL vulnerabilities in your apps") (新規アプリケーションおよび更新の両方) 。
