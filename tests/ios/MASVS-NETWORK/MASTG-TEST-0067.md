---
masvs_v1_id:
- MSTG-NETWORK-3
masvs_v2_id:
- MASVS-NETWORK-1
platform: ios
title: エンドポイント同一性検証のテスト (Testing Endpoint Identity Verification)
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## 概要

## 静的解析

TLS を使用して機密情報をネットワーク上で転送することはセキュリティにとって不可欠です。しかし、モバイルアプリケーションとバックエンド API 間の通信を暗号化することは簡単ではありません。開発者は開発プロセスを容易にするためにより単純だがセキュアとはいい難いソリューション (例えば、任意の証明書を受け入れるもの) を決定することがよくあり、時にはこれらの弱いソリューションが製品版に組み込まれることがあり、ユーザーを [中間マシン (Machine-in-the-Middle, MITM)](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) 攻撃にさらす可能性があります。["CWE-295: Improper Certificate Validation"](https://cwe.mitre.org/data/definitions/295.html "CWE-295: Improper Certificate Validation") を参照してください。

これらは対処すべき問題の一部です。

- アプリが iOS 9.0 より古い SDK に対してリンクされているかどうかを確認します。この場合、アプリがどのバージョンの OS で実行されても ATS は無効になります。
- 証明書が信頼するソース、すなわち信頼できる CA (認証局) からのものであることを検証する。
- エンドポイントサーバーが正しい証明書を提示しているかどうかを判断します。

ホスト名と証明書自体が正しく検証されていることを確認します。例やよくある落とし穴は [Apple 公式ドキュメント](https://developer.apple.com/documentation/security/preventing_insecure_network_connections "Preventing Insecure Network Connections") に掲載されています。

動的解析で静的解析をサポートすることを強くお勧めします。ソースコードがない場合やリバースエンジニアリングが困難なアプリの場合、堅実な動的解析戦略が必ず役立ちます。その場合、アプリが低レベル API や高レベル API を使用しているかどうかはわかりませんが、依然としてさまざまな信頼性評価シナリオをテストできます (例: 「アプリは自己署名証明書を受け入れるか？」) 。

## 動的解析

私たちのテストアプローチは SSL ハンドシェイクネゴシエーションのセキュリティを少しずつ緩めて、どのセキュリティメカニズムが有効であるかを確認することです。

1. Burp をプロキシとして設定した後、トラストストア (**Settings** -> **General** -> **Profiles**) に証明書が追加されていないこと、および SSL キルスイッチなどのツールが無効であることを確認します。アプリケーションを起動して、Burp にトラフィックが表示されるかどうかを確認します。問題がある場合は 'Alerts' タブに報告されます。トラフィックが見える場合、証明書検証がまったく実行されていないことを意味します。そうではなく、トラフィックを見ることができず、SSL ハンドシェイクの失敗に関する情報がある場合には、次の項目に従います。
2. 次に、[Burp のユーザードキュメント](https://support.portswigger.net/customer/portal/articles/1841109-installing-burp-s-ca-certificate-in-an-ios-device "Installing Burp\'s CA Certificate in an iOS Device") で説明されているように、Burp 証明書をインストールします。ハンドシェイクが成功して Burp でトラフィックを見ることができる場合、デバイスのトラストストアに対して証明書が検証されているが、ピン留めが実行されていないことを意味します。

前のステップの手順を実行してもトラフィックがプロキシされない場合は、証明書ピン留めが実際に実装され、すべてのセキュリティ対策が実施されていることを意味している可能性があります。しかし、アプリケーションをテストするには依然としてピン留めをバイパスする必要があります。この詳細については [証明書ピン留めのバイパス (Bypassing Certificate Pinning)](../../../techniques/ios/MASTG-TECH-0064.md) を参照してください。
