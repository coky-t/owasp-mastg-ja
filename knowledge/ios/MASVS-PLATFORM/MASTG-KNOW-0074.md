---
masvs_category: MASVS-PLATFORM
platform: ios
title: 強制アップデート (Enforced Updating)
---

強制アップデートは、公開鍵のピン留め (詳細についてはネットワーク通信のテストを参照) において、証明書/公開鍵ローテンションによりピンをリフレッシュする必要がある場合に役立つ可能性があります。さらに、強制アップデートによって脆弱性に簡単にパッチ適用できます。

しかし iOS の課題は、Apple がこのプロセスを自動化する API をまだ提供していないことです。代わりに、開発者はさまざまな [ブログ](https://mobikul.com/show-update-application-latest-version-functionality-ios-app-swift-3/ "Updating version in Swift 3") で説明されているような独自のメカニズムを作成する必要があります。これは `http://itunes.apple.com/lookup\?id\<BundleId>` を使用してアプリのプロパティを調べるか、[Siren](https://github.com/ArtSabintsev/Siren "Siren") や [react-native-appstore-version-checker](https://www.npmjs.com/package/react-native-appstore-version-checker "Update checker for React") などのサードパーティライブラリを使用することです。これらの実装のほとんどは、API によって提供される特定のバージョン、または単に「アプリストアの最新」を必要とします。つまり、実際にはビジネス上またはセキュリティ上のアップデートの必要性がないにもかかわらず、ユーザーはアプリをアップデートしなければならないことに苛立ちを感じる可能性があります。

アプリケーションの新しいバージョンはアプリが通信するバックエンドに存在するセキュリティ問題を修正しないことに注意してください。アプリがそれと通信できないようにするだけでは十分ではないかもしれません。適切な API ライフサイクル管理を持つことがここでは重要です。
同様に、ユーザーにアップデートを強制しない場合でも、古いバージョンのアプリを API でテストし、適切な API バージョン管理を使用することを忘れてはいけません。
