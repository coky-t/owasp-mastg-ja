---
platform: ios
title: クリアテキストトラフィックのための低レベルネットワーク API の使用 (Uses of Low-Level Networking APIs for Cleartext Traffic)
id: MASTG-TEST-0323
type: [static, code, manual]
weakness: MASWE-0050
profiles: [L1, L2]
knowledge: [MASTG-KNOW-0073]
---

## 概要

App Transport Security (ATS) は [URL Loading System](https://developer.apple.com/documentation/foundation/url_loading_system) (通常は `URLSession`) を介した接続に対してのみ適用します。低レベルネットワーク API は ATS をすべてバイパスするため、アプリの ATS 構成に関係なく、クリアテキスト HTTP 接続を確立できることを意味します。

以下の低レベル API は ATS に影響をうけません。

- **[`Network` フレームワーク](https://developer.apple.com/documentation/network)**: TCP および UDP を使用したソケットレベル通信のための最新の低レベルネットワーク API。
- **[`CFNetwork`](https://developer.apple.com/documentation/cfnetwork)**: `CFSocketStream`, `CFHTTPStream`, および関連関数を含む Core Foundation ベースのネットワーク API。
- **BSD ソケット**: `socket()`, `connect()`, `send()`, `recv()` などの関数を通じてアクセスされる低レベル POSIX ソケット API。

Apple は高レベルフレームワークを優先することを [推奨しています](https://developer.apple.com/documentation/security/preventing_insecure_network_connections)。「ATS はアプリが `Network` フレームワークや `CFNetwork` などの低レベルネットワークインタフェースを呼び出す際には適用しません。これらのケースでは、接続のセキュリティを確保するのはあなたの責任です。この方法で安全な接続を構築できますが、ミスが生じやすく、コストもかかります。通常は代わりに URL Loading System を頼りにするのが最も安全です。」

ATS 適用の際の詳細については [iOS App Transport Security](../../../knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0071.md) を参照してください。

## 手順

1. [アプリパッケージの探索 (Exploring the App Package)](../../../techniques/ios/MASTG-TECH-0058.md) を使用して、アプリパッケージから関連するバイナリを抽出します。
2. [iOS での静的解析 (Static Analysis on iOS)](../../../techniques/ios/MASTG-TECH-0066.md) を使用して、アプリバイナリ内の関連する API を探します。

## 結果

出力には低レベルネットワーク API 使用とアプリバイナリ内のそれらの場所のリストを含む可能性があります。

## 評価

アプリが低レベルネットワーク API を使用してクリアテキスト接続を確立する場合、そのテストケースは不合格です。

**さらなるバリデーションが必要となります:**

[逆アセンブルされた Objective-C と Swift のコードをレビューする (Reviewing Disassembled Objective-C and Swift Code)](../../../techniques/ios/MASTG-TECH-0076.md) を使用して報告された各コード箇所を検査し、クリアテキストが確立されているかどうかを判断します。

- `Network` フレームワーク接続で TLS が構成されているかどうかを判断します。たとえば、`NWParameters` に `.tls` が含まれているかどうかをチェックします。
- `CFNetwork` または BSD ソケット接続が任意の TLS ラッパーを使用するかどうかを判断します。
