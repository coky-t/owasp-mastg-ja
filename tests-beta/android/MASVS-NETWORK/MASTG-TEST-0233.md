---
title: ハードコードされた HTTP URL (Hardcoded HTTP URLs)
platform: android
id: MASTG-TEST-0233
type: [static]
weakness: MASWE-0050
related-tests: [MASTG-TEST-0235, MASTG-TEST-0236, MASTG-TEST-0238]
profiles: [L1, L2]
---

## 概要

Android アプリは APK 内のアプリバイナリ、ライブラリバイナリ、その他のリソースにハードコードされた HTTP URL が埋め込まれていることがあります。これらの URL はアプリが暗号化されていない接続を介してサーバーと通信する潜在的な場所を示している可能性があります。

> [!WARNING]
> 制限事項 - HTTP URL の存在だけでは、必ずしも実際に通信に使用されていることを意味するわけではありません。URL の呼び出し方法や、アプリの構成でクリアテキストトラフィックが許可されているかどうかなど、それらの使用状況は実行時の状態によって異なることがあります。たとえば、AndroidManifest.xml でクリアテキストトラフィックが無効にされていたり、Network Security Configuration によって制限されていると、HTTP リクエストは失敗することがあります。[クリアテキストトラフィックを許可している Android アプリ構成 (Android App Configurations Allowing Cleartext Traffic)](MASTG-TEST-0235.md) を参照してください。

## 手順

1. アプリをリバースエンジニアします ([Java コードの逆コンパイル (Decompiling Java Code)](../../../techniques/android/MASTG-TECH-0017.md))。
2. アプリに対して静的解析 ([Android での静的解析 (Static Analysis on Android)](../../techniques/android/MASTG-TECH-0014.md)) ツールを実行して、`http://` URL を探します。

## 結果

出力には URL とアプリ内の場所のリストを含みます。

## 評価

HTTP URL が通信に使用されていることを確認された場合、そのテストケースは不合格です。

ハードコードされた HTTP URL の存在は、実際に使用されていることを意味するわけではありません。実際の使用状況は慎重な検査とテストによって検証しなければなりません。

- **リバースエンジニアリング**: HTTP URL が参照されているコードの場所を検査します。単に定数として保存されているだけなのか、`HttpURLConnection` や `OkHttp` などのネットワーク API を介して HTTP リクエストを作成するために実際に使用されているのかを判断します。
- **静的解析**: アプリの構成を解析して、クリアテキストトラフィックが許可されているかどうかを特定します。たとえば、AndroidManifest.xml の `android:usesCleartextTraffic="true"` をチェックするか、`network_security_config` を検査します。詳細なガイダンスについては [クリアテキストトラフィックを許可している Android アプリ構成 (Android App Configurations Allowing Cleartext Traffic)](MASTG-TEST-0235.md) を参照してください。

さらに、この静的検査を動的テスト手法で補完します。

- **動的解析**: Frida などのツールを使用して、実行時にネットワーク API にフックします。これにより実行時に HTTP URL がいつどのように使用されるかを明らかにできます。詳細は [クリアテキストトラフィックを転送するネットワーク API の実行時使用 (Runtime Use of Network APIs Transmitting Cleartext Traffic)](MASTG-TEST-0238.md) を参照してください。

- **ネットワークトラフィック傍受**: Burp Suite, mitmproxy, Wireshark などのツールを使用して、ネットワークトラフィックをキャプチャし、解析します。このアプローチは、実際の使用時に特定した HTTP URL にアプリが接続するかどうかを確認しますが、アプリの機能を包括的に実行するテスト担当者の能力に依存します。[ネットワーク上で観測されるクリアテキストトラフィック (Cleartext Traffic Observed on the Network)](MASTG-TEST-0236.md) を参照してください。
