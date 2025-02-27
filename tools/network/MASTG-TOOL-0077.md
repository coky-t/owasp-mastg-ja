---
title: Burp Suite
platform: network
source: https://portswigger.net/burp/communitydownload
---

Burp Suite は、モバイルアプリケーションとウェブアプリケーションのセキュリティテストを実行するための統合プラットフォームです。

このツールはシームレスに連携して、攻撃対象領域の初期マッピングと解析からセキュリティ脆弱性の発見と悪用まで、テストプロセス全体をサポートします。Burp Proxy は、ブラウザとウェブサーバー間の中間マシン (Machine-in-the-Middle, MITM) として位置づけられる Burp Suite のウェブプロキシサーバーとして動作します。Burp Suite は、送受信される生の HTTP トラフィックを傍受、検査、改変できます。

Burp をセットアップしてトラフィックをプロキシするのはとても簡単です。デバイスとホストコンピュータの両方が、クライアント間トラフィックを許可する Wi-Fi ネットワークに接続されていると仮定します。

PortSwigger は、Burp で動作するように Android デバイスと iOS デバイスの両方をセットアップするための優れたチュートリアルを提供しています。

- [Configuring an Android Device to Work With Burp](https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp "Configuring an Android Device to Work With Burp").
- [Installing Burp's CA certificate to an Android device](https://support.portswigger.net/customer/portal/articles/1841102-installing-burp-s-ca-certificate-in-an-android-device "Installing Burp\'s CA Certificate in an Android Device").
- [Configuring an iOS Device to Work With Burp](https://support.portswigger.net/customer/portal/articles/1841108-configuring-an-ios-device-to-work-with-burp "Configuring an iOS Device to Work With Burp").
- [Installing Burp's CA certificate to an iOS device](https://support.portswigger.net/customer/portal/articles/1841109-installing-burp-s-ca-certificate-in-an-ios-device "Installing Burp\'s CA Certificate in an iOS Device").

詳細については [傍受プロキシの設定 (Setting Up an Interception Proxy)](../../techniques/android/MASTG-TECH-0011.md) (Android) および [傍受プロキシの設定 (Setting Up an Interception Proxy)](../../techniques/ios/MASTG-TECH-0063.md) (iOS) を参照してください。
