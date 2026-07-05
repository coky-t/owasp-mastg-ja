---
platform: android
title: ネットワークトラフィックキャプチャにおける宣言されていない PII (Undeclared PII in Network Traffic Capture)
id: MASTG-TEST-0206
type:
  - dynamic
  - network
weakness: MASWE-0108
prerequisites:
  - identify-sensitive-data
  - privacy-policy
  - app-store-privacy-declarations
profiles:
  - P
---

# MASTG-TEST-0206 ネットワークトラフィックキャプチャにおける宣言されていない PII (Undeclared PII in Network Traffic Capture)

### 概要

攻撃者は [ZAP (Zed Attack Proxy)](../../../tools/network/MASTG-TOOL-0079.md)、[Burp Suite](../../../tools/network/MASTG-TOOL-0077.md)、[mitmproxy](../../../tools/network/MASTG-TOOL-0097.md) などの傍受プロキシを使用して Android デバイスからのネットワークトラフィックをキャプチャし、アプリから送信されるデータを解析できます。これはアプリが HTTPS を使用している場合でも機能します。攻撃者は Android デバイスにカスタムルート証明書をインストールしてトラフィックを復号できるためです。HTTPS で暗号化されていないトラフィックの検査はさらに簡単で、たとえば [Wireshark](../../../tools/network/MASTG-TOOL-0081.md) を使用することで、カスタムルート証明書をインストールすることなく実行できます。

このテストの目的は、トラフィックが暗号化されている場合でも、機密データ (特に PII) がネットワーク経由で送信されていないことを検証することです。このテストは、金融データや医療データなどの機密データを扱うアプリにとって特に重要であり、アプリのプライバシーポリシーとアプリのマーケットプレイスのプライバシー宣言 (Google Play の Data Safety セクションなど) のレビューと併せて実施すべきです。

### 手順

1. [アプリのインストール (Installing Apps)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/android/MASTG-TECH-0005.md) を使用して、アプリをインストールします。
2. [ネットワークトラフィックからの機密データのログ記録 (Logging Sensitive Data from Network Traffic)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/android/MASTG-TECH-0100.md) を使用して、アプリのネットワークトラフィックをキャプチャしログ記録します。
3. アプリを起動して使用し、さまざまなワークフローを実行しながら、可能な場所で機密データを入力します。特に、ネットワークトラフィックをトリガーすることが分かっている場所で行います。

### 結果

出力には復号された HTTPS トラフィックを含むネットワークトラフィックのログを含む可能性があります。

### 評価

アプリのマーケットプレイスのプライバシー宣言 (Google Play の Data Safety セクションなど) やそのプライバシーポリシーに宣言されていない、アプリに入力した PII を見つけることができた場合、そのテストケースは不合格です。

このテストは、機密データがネットワーク経由で送信されるコードの場所を提供しないことに注意してください。コードの場所を特定するには [Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md) や [MASTG-TECH-0015 Android での動的解析 (Dynamic Analysis on Android)](../../../techniques/android/MASTG-TECH-0015.md) を使用できます。詳細については、それぞれ [機密ユーザーデータを扱うことが知られている SDK API への参照 (References to SDK APIs Known to Handle Sensitive User Data)](MASTG-TEST-0318.md) および [機密ユーザーデータを扱うことが知られている SDK API の実行時使用 (Runtime Use of SDK APIs Known to Handle Sensitive User Data)](MASTG-TEST-0319.md) を参照してください。
