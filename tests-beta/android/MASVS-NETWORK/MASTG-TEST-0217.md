---
title: コード内で明示的に許可された安全でない TLS プロトコル (Insecure TLS Protocols Explicitly Allowed in Code)
platform: android
id: MASTG-TEST-0217
type: [static]
weakness: MASWE-0050
profiles: [L1, L2]
---

## 概要

Android Network Security Configuration は特定の TLS バージョンを直接制御することはできません ([iOS](https://developer.apple.com/documentation/bundleresources/information_property_list/nsexceptionminimumtlsversion) とは異なります)。Android 10 以降では、すべての TLS 接続に対して [TLS v1.3 がデフォルトで有効になっています](https://developer.android.com/privacy-and-security/security-ssl#Updates%20to%20SSL)。

安全でないバージョンの TLS を有効にする方法は、以下のように、まだいくつかあります。

### Java ソケット

アプリは `SSLContext.getInstance("TLSv1.1")` を呼び出すことによって、安全でない TLS プロトコルを使用する SSLContext を取得できます。また、API コール `javax.net.ssl.SSLSocket.setEnabledProtocols(String[] protocols)` を使用して、潜在的に安全でない特定のプロトコルバージョンを有効にすることもできます。

### サードパーティライブラリ

[OkHttp](https://square.github.io/okhttp/), [Retrofit](https://square.github.io/retrofit/), Apache HttpClient などの一部のサードパーティライブラリは TLS プロトコルのカスタム構成を提供しています。これらのライブラリは慎重に管理しないと古いプロトコルを有効にしてしまう可能性があります。

たとえば、OkHttp で (`okhttp3.ConnectionSpec.Builder.connectionSpecs(...)` 経由で) `ConnectionSpec.COMPATIBLE_TLS` を使用すると、バージョンによっては TLS 1.1 などの安全でない TLS バージョンがデフォルトで有効になってしまうことがあります。サポートされているプロトコルの詳細については OkHttp の [configuration history](https://square.github.io/okhttp/security/tls_configuration_history/) を参照してください。

API コール `okhttp3.ConnectionSpec.Builder.tlsVersions(...)` を使用して、有効なプロトコルを設定することもできます ([OkHttp ドキュメント](https://square.github.io/okhttp/features/https/))。

## 手順

1. アプリをリバースエンジニアします ([Java コードの逆コンパイル (Decompiling Java Code)](../../../techniques/android/MASTG-TECH-0017.md))。
2. リバースエンジニアしたアプリに対して、TLS プロトコルを設定する API の呼び出しをターゲットとした静的解析 ([Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md)) ツールを実行します。

## 結果

出力には上記の API コールで有効になっているすべての TLS バージョンのリストを含む可能性があります。

## 評価

[安全でない TLS バージョン](../../../Document/0x04f-Testing-Network-Communication.md#recommended-tls-settings) が直接有効になっているか、アプリが `okhttp3.ConnectionSpec.COMPATIBLE_TLS` などの古い TLS バージョンの使用を許可する設定を有効にしている場合、テストケースは不合格です。
