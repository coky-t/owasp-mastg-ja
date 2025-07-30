---
masvs_category: MASVS-CRYPTO
platform: android
title: セキュリティプロバイダ (Security Provider)
---

Android は `java.security.Provider` クラスを介した [セキュリティプロバイダ](https://developer.android.com/privacy-and-security/security-gms-provider "セキュリティプロバイダを更新して SSL エクスプロイトから保護する") に依存して、Java Security サービスを実装し、SSL/TLS ベースの接続を提供します。これらのプロバイダは安全なネットワーク通信と、暗号に依存するその他の安全な機能を確保するために重要です。Android に含まれるセキュリティプロバイダのリストは Android のバージョンや OEM 固有のビルドによって異なります。

この種のセキュリティプロバイダの問題 (一例として [OpenSSL](https://www.openssl.org/news/vulnerabilities.html "OpenSSL Vulnerabilities")) はデバイスに付随するもので、多くの場合バグや脆弱性があります。したがって、 Android アプリケーションは正しいアルゴリズムを選択して適切な構成を提供するだけでなく、場合によってはレガシーセキュリティプロバイダの実装の強度にも注意を払う必要があります。

既知の脆弱性を回避するために、開発者はアプリケーションが適切なセキュリティプロバイダをインストールすることを確認する必要があります。
2016年7月11日以降、Google は脆弱なバージョンの OpenSSL を使用している [Play ストアアプリケーションの提出を拒否しています](https://support.google.com/faqs/answer/6376725?hl=en "How to address OpenSSL vulnerabilities in your apps") (新規アプリケーションとアップデートの両方)。

## 利用可能なセキュリティプロバイダの一覧

以下のコードを使用して既存のセキュリティプロバイダのセットを一覧表示できます。

```java
StringBuilder builder = new StringBuilder();
for (Provider provider : Security.getProviders()) {
    builder.append("provider: ")
            .append(provider.getName())
            .append(" ")
            .append(provider.getVersion())
            .append("(")
            .append(provider.getInfo())
            .append(")\n");
}
String providers = builder.toString();
//now display the string on the screen or in the logs for debugging.
```

これは Google Play API を備えたエミュレータで実行中の Android 9 (API レベル 28) の出力です。

```default
provider: AndroidNSSP 1.0(Android Network Security Policy Provider)
provider: AndroidOpenSSL 1.0(Android's OpenSSL-backed security provider)
provider: CertPathProvider 1.0(Provider of CertPathBuilder and CertPathVerifier)
provider: AndroidKeyStoreBCWorkaround 1.0(Android KeyStore security provider to work around Bouncy Castle)
provider: BC 1.57(BouncyCastle Security Provider v1.57)
provider: HarmonyJSSE 1.0(Harmony JSSE Provider)
provider: AndroidKeyStore 1.0(Android KeyStore security provider)
```

## セキュリティプロバイダの更新

コンポーネントに最新のパッチを適用し続けることはセキュリティ原則の一つです。同じことが `provider` にも当てはまります。アプリケーションは使用されているセキュリティプロバイダが最新かどうかを確認し、最新でない場合には [更新してください](https://developer.android.com/training/articles/security-gms-provider "Updating security provider") 。

## 旧バージョンの Android

古いバージョンの Android (例: Android 7.0 (API レベル 24) より以前のバージョンでのみ使用される) をサポートする一部のアプリケーションでは、最新のライブラリをバンドルすることが唯一の選択肢かもしれません。Conscrypt ライブラリはさまざまな API レベルで暗号化の一貫性を保ち、より重いライブラリである [Bouncy Castle](https://www.bouncycastle.org/documentation/documentation-java/ "Bouncy Castle in Java") をインポートする必要がないようにするため、この状況では適切な選択といえます。

[Conscrypt for Android](https://github.com/google/conscrypt#android "Conscrypt - A Java Security Provider") は以下の方法でインポートできます。

```groovy
dependencies {
  implementation 'org.conscrypt:conscrypt-android:last_version'
}
```

次に、以下を呼び出してプロバイダを登録する必要があります。

```kotlin
Security.addProvider(Conscrypt.newProvider())
```
