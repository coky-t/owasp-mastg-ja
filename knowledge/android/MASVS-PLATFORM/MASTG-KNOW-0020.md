---
masvs_category: MASVS-PLATFORM
platform: android
title: プロセス間通信 (IPC) メカニズム (Inter-Process Communication (IPC) Mechanisms)
---

モバイルアプリケーションの実装において、開発者は IPC の従来の技法 (共有ファイルやネットワークソケットの使用など) を適用することがあります。モバイルアプリケーションプラットフォームが提供する IPC システム機能は、従来の技法よりもはるかに成熟しているため、使用すべきです。セキュリティを考慮せずに IPC メカニズムを使用すると、アプリケーションが機密データを漏洩したり露出する可能性があります。

以下は機密データを露出する可能性のある Android IPC メカニズムの一覧です。

- [バインダ](https://developer.android.com/reference/android/os/Binder.html "Binder")
- [AIDL](https://developer.android.com/guide/components/aidl.html "AIDL")
- [インテント](https://developer.android.com/reference/android/content/Intent.html "Intent")
- [コンテンツプロバイダ](https://developer.android.com/reference/android/content/ContentProvider.html "ContentProvider")
- [サービス](https://developer.android.com/guide/components/services.html "Services")
