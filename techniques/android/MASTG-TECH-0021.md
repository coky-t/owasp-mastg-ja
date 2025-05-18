---
title: 情報収集 - API の使用 (Information Gathering - API Usage)
platform: android
---

Android プラットフォームは、暗号化、Bluetooth、NFC、ネットワーク、位置情報ライブラリなど、アプリケーションで頻繁に使用される機能のために多くの組み込みライブラリを提供しています。アプリケーションにこれらのライブラリが存在するかどうかを判断することで、そのアプリケーションの性質に関する貴重な情報を得ることができます。

たとえば、アプリケーションが `javax.crypto.Cipher` をインポートしている場合、アプリケーションがなんらかの暗号操作を実行することを示しています。幸いなことに、暗号化の呼び出しは本質的に非常に標準的です。つまり、正しく動作するには特定の順序で呼び出す必要があり、この知識は暗号 API を解析する際に役立ちます。たとえば、`Cipher.getInstance` 関数を探すことで、使用されている暗号アルゴリズムを特定できます。このようなアプローチにより、アプリケーションにおいて非常に重要であることが多い暗号資産の解析に直接進むことができます。Android の暗号 API を解析方法の詳細については "[Android の暗号化 API](../../Document/0x05e-Testing-Cryptography.md "Android の暗号化 API")" のセクションで説明しています。

同様に、上記のアプローチを使用して、アプリケーションが NFC をどこでどのように使用しているかを判断できます。たとえば、デジタル決済を実行するためにホストベースのカードエミュレーションを使用するアプリケーションは `android.nfc` パッケージを使用する必要があります。したがって、NFC API 解析の良い出発点は [Android 開発者ドキュメント](https://developer.android.com/guide/topics/connectivity/nfc/hce "Host-based card emulation overview") を参照していくつかのアイデアを得て、`android.nfc.cardemulation.HostApduService` クラスの `processCommandApdu` などの重要な関数を探し始めることでしょう。
