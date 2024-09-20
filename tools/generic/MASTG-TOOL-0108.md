---
title: Corellium
platform: generic
source: https://corellium.com
---

Corellium は iOS および Android デバイスの仮想化プラットフォームであり、ユーザーが仮想デバイスを作成および管理し、動的解析を実行し、制御された環境でアプリケーションをテストできます。

## 概要

Corellium は、ユーザーが仮想化された iOS および Android デバイスを実行できる、クラウドベースのソリューションを提供します。これらの仮想デバイスは、セキュリティテスト、アプリ開発、研究など、さまざまな目的に使用できます。Corellium は、仮想デバイスを管理するためのウェブベースのインタフェースと、自動化と他のツールとの統合のための API を提供します。

Corellium GUI は、アプリの概要、アプリのインストーラ、およびセキュリティテストに役立つ以下のような多くの機能を提供しています。

- [ビルトインファイルブラウザ](https://support.corellium.com/features/files/)
- [ビルトイン Frida サーバー](https://support.corellium.com/features/frida/)
- [スナップショットマネージメント](https://support.corellium.com/features/snapshots)
- [ネットワークモニタ](https://support.corellium.com/features/network-monitor/)

## iOS エミュレーション

Corellium は [iOS エミュレーション](https://support.corellium.com/devices/ios) の唯一の商用オプションです。サポートされている iOS バージョンであれば、あらゆるタイプの iOS デバイスを起動できます。各デバイスは最初から脱獄できるので、最新バージョンの iOS でもアプリケーションの解析に使用できます。

Corellium にはアプリケーションと iOS 自体の両方を解析するための非常に強力なツールがいくつかありますが、いくつか重要な制限があります。

- **App Store なし**: デバイスには App Store がないため、Corellium デバイスを使用して IPA ファイルの復号化したバージョンを取得することはできません。
- **Apple サービスなし**: Apple サービス (iMessage やプッシュ通知を含む) へのアクセスは利用できません。
- **カメラ / 電話 / NFC / Bluetooth なし**: Corellium 上で動作するアプリはこれらの周辺機器にアクセスできません。ただし [SMS の擬似送信](https://support.corellium.com/features/messaging) はサポートしています。

iOS テストの詳細については [こちら](https://support.corellium.com/features/apps/testing-ios-apps) をご覧ください。

## Android エミュレーション

[Android エミュレーション](https://support.corellium.com/devices/android) は `user` と `userdebug` の両方の構成で利用可能であり、すべてのイメージはデフォルトでルート化されています。Google Play やその他の Goole サービスはデフォルトではインストールされませんが、Corellium では [OpenGApps](https://support.corellium.com/features/apps/opengapps) パッケージを介してインストールできます。[Bluetooth](https://support.corellium.com/features/apps/bluetooth) がサポートされています。

但し、いくつかの機能はサポートしていません。

- **TrustZone**: Keymaster にアクセスしたり、PlayReady や Widevine を使用することはできません。
- **Permissive モードの SELinux**: SELinux が Permissive モードに設定されていると、アプリケーションで検出されるかもしれません。これは一般的に Magisk や KernelSU でルート化された物理デバイスには当てはまりません。

Android テストの詳細については [こちら](https://support.corellium.com/features/apps/debug-test-android-apps) をご覧ください。
