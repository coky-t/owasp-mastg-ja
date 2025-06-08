---
platform: android
title: ネットワークトラフィックキャプチャにおける機密データ (Sensitive Data in Network Traffic Capture)
id: MASTG-TEST-0206
type: [dynamic, network]
weakness: MASWE-0108
prerequisites:
- identify-sensitive-data
- privacy-policy
- app-store-privacy-declarations
profiles: [P]
---

## 概要

攻撃者は [ZAP](../../../tools/network/MASTG-TOOL-0079.md)、[Burp Suite](../../../tools/network/MASTG-TOOL-0077.md)、[mitmproxy](../../../tools/network/MASTG-TOOL-0097.md) などの傍受プロキシを使用して Android デバイスからのネットワークトラフィックをキャプチャし、アプリから送信されるデータを解析できます。これはアプリが HTTPS を使用している場合でも機能します。攻撃者は Android デバイスにカスタムルート証明書をインストールしてトラフィックを復号できるためです。HTTPS で暗号化されていないトラフィックの検査はさらに簡単で、たとえば [Wireshark](../../../tools/network/MASTG-TOOL-0081.md) を使用することで、カスタムルート証明書をインストールすることなく実行できます。

このテストの目的は、トラフィックが暗号化されている場合でも、機密データがネットワーク経由で送信されていないことを検証することです。このテストは、金融データや医療データなどの機密データを扱うアプリにとって特に重要であり、アプリのプライバシーポリシーと App Store のプライバシー宣言のレビューと併せて実施すべきです。

## 手順

1. デバイスを起動します。
2. ネットワークトラフィックからの機密データのログ記録を開始します ([ネットワークトラフィックからの機密データのログ記録 (Logging Sensitive Data from Network Traffic)](../../../techniques/android/MASTG-TECH-0100.md))。たとえば、[mitmproxy](../../../tools/network/MASTG-TOOL-0097.md) を使用します。
3. アプリを起動して使用し、さまざまなワークフローを実行しながら、可能な場所で機密データを入力します。特に、ネットワークトラフィックをトリガーすることが分かっている場所で行います。

## 結果

出力には復号された HTTPS トラフィックを含むネットワークトラフィックの機密データログを含む可能性があります。

## 評価

App Store のプライバシー宣言に記載されていない、アプリに入力した機密データを見つけることができた場合、そのテストケースは不合格です。

このテストは、機密データがネットワーク経由で送信されるコードの場所を提供しないことに注意してください。コードの場所を特定するには、[semgrep](../../../tools/generic/MASTG-TOOL-0110.md) などの静的解析ツールや [Frida](../../../tools/generic/MASTG-TOOL-0031.md) などの動的解析ツールを使用できます。
