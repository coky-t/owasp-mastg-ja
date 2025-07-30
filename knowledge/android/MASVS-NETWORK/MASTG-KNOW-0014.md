---
masvs_category: MASVS-NETWORK
platform: android
title: Android Network Security Configuration
---

Android 7.0 (API レベル 24) 以降、Android アプリはいわゆる [Network Security Configuration](https://developer.android.com/training/articles/security-config) 機能を使用して、ネットワークセキュリティ設定をカスタマイズできます。これは以下の主要な機能を提供します。

- **クリアテキストトラフィック**: クリアテキストトラフィックの偶発的な使用からアプリを保護します (またはそれを有効にします) 。
- **カスタムトラストアンカー**: アプリのセキュア接続のために信頼する認証局 (Certificate Authority, CA) をカスタマイズできます。たとえば、特定の自己署名証明書を信頼したり、アプリが信頼するパブリック CA のセットを制限します。
- **証明書ピンニング**: アプリのセキュア接続を特定の証明書に制限します。
- **デバッグのみのオーバーライド**: インストールベースへの追加リスクなしに、アプリのセキュア接続を安全にデバッグします。

アプリがカスタム Network Security Configuration を定義している場合、AndroidManifest.xml ファイルの `android:networkSecurityConfig` を探すことでその場所を取得できます。

```xml
<application android:networkSecurityConfig="@xml/network_security_config"
```

この場合、ファイルは `@xml` (/res/xml と同じ) にあり、名前は "network_security_config" (異なることがあります) です。 "res/xml/network_security_config.xml" として見つけることができるはずです。コンフィグレーションが存在する場合、システムログ ([システムログの監視 (Monitoring System Logs)](../../../techniques/android/MASTG-TECH-0009.md)) に以下のイベントが表示されるはずです。

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

- ["A Security Analyst's Guide to Network Security Configuration in Android P"](https://www.nowsecure.com/blog/2018/08/15/a-security-analysts-guide-to-network-security-configuration-in-android-p/)
- [Android Developers - Network Security Configuration](https://developer.android.com/training/articles/security-config)
- [Android Codelab - Network Security Configuration](https://developer.android.com/codelabs/android-network-security-config)

## デフォルトコンフィグレーション

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
