---
title: GMS セキュリティプロバイダを更新する (Update the GMS Security Provider)
alias: update-gms-security-provider
id: MASTG-BEST-0020
platform: android
knowledge: [MASTG-KNOW-0011]
---

Android デバイスは OS バージョンとアップデート頻度が大きく異なります。プラットフォームレベルのセキュリティだけに依存すると、アプリが古い SSL/TLS 実装や既知の脆弱性にさらされる可能性があります。

**GMS セキュリティプロバイダ** (Google Play Services 経由で配信) は、`OpenSSL` や `TrustManager` などの重要な暗号化コンポーネントを **Android OS とは独立して** 更新することで、これを対処します。これは、古いデバイスやパッチが適用されていないデバイスでも、**安全なネットワーク通信** を確保できます。

**アプリ起動時の初期段階**、できれば安全なネットワーク通信を確立する前に、セキュリティプロバイダをチェックして更新することを強くお勧めします。[SSL エクスプロイトから保護するためのセキュリティプロバイダの更新方法](https://developer.android.com/privacy-and-security/security-gms-provider "Updating Your Security Provider to Protect Against SSL Exploits") については、Android 開発者ドキュメントに従ってください。

アプリが **Google Play Services 搭載および非搭載** の両方のデバイス (Huawei デバイス、Amazon タブレット、AOSP ベースの ROM など) をサポートする必要がある場合、Play Services の可用性を検出するためのランタイムチェックを実装します。

- GMS 対応デバイスでは、セキュリティプロバイダを使用して暗号化ライブラリを最新の状態に保ちます。
- GMS 非対応デバイスでは、[Conscrypt](https://conscrypt.org) などの安全な TLS ライブラリをバンドルして、デバイスフリート全体で一貫した強力なネットワークセキュリティを確保することを考慮してください。
