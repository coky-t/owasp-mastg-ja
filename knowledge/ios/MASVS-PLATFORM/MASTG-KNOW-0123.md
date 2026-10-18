---
masvs_category: MASVS-PLATFORM
platform: ios
title: ハンドオフ (Handoff)
available_since: 8
---

ハンドオフは、ユーザーがあるデバイスでアクティビティを始め、それを別の近くにある Apple デバイスに引き継ぐ、Apple の連携機能です。これは [`NSUserActivity`](https://developer.apple.com/documentation/foundation/nsuseractivity) を頼りに、後からアクティビティを再開するために必要な状態を捕捉します。

## ハンドオフの仕組み

アプリは、現在のアクティビティを記述する `NSUserActivity` オブジェクトを作成して、それを現在とします。ハンドオフは、対象となるユーザーアクティビティを、同じ iCloud アカウントにサインインしている近くのデバイスに通知します。ユーザーが別のデバイス上でハンドオフを受け入れると、システムはそのデバイス上でアプリを起動または再開し、`NSUserActivity` をそれに引き渡します。

`NSUserActivity` は、ユニバーサルリンク ([ユニバーサルリンク (Universal Links)](MASTG-KNOW-0080.md) 参照)、Siri の提案、Spotlight との統合など、関連するプラットフォーム機能でも使用されます。これは、アプリによって設定された適格性フラグによっては、同一のアクティビティデータが複数のシステム機能に影響を及ぼす可能性があることを意味します。

アプリはハンドオフを以下のように取り入れます。

1. `Info.plist` で宣言した `activityType` とともに `NSUserActivity` を作成して設定します。
2. アクティビティを復元するために必要なデータを `userInfo` に入力します。
3. そのアクティビティがハンドオフの対象であることを [`isEligibleForHandoff`](https://developer.apple.com/documentation/foundation/nsuseractivity/iseligibleforhandoff) を通じて確認します。
4. [`becomeCurrent()`](https://developer.apple.com/documentation/foundation/nsuseractivity/becomecurrent()) を呼び出し、そのアクティビティを現在のものとします。
5. シーンベースのアプリでは、[`scene(_:continue:)`](https://developer.apple.com/documentation/uikit/uiscenedelegate/scene(_:continue:)) を実装して、そのアクティビティを受け取り復元します。シーンを使用しないアプリでは、非推奨の [`application(_:continue:restorationHandler:)`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/application(_:continue:restorationhandler:)) を通じて継続を処理します。

## スコープと制約

- ハンドオフは、同じ iCloud アカウントでサインインしている、近くにある Apple デバイス間で機能します。
- `activityType` は、アプリの `Info.plist` 内の `NSUserActivityTypes` の下で宣言されなければなりません。
- `userInfo` を介して転送されるデータは最小限に抑えるべきです。Apple は、ペイロードを可能な限り小さく、できれば 3 KB 以下に、して転送することを推奨しています。より大きな状態には、そのデータを他の場所に保存し、それを取得や再構築するためにちょうど十分な情報を含めます。
- アクティビティがファイル URL を含む場合、受け取り側のアプリはそれらにアクセスする前に `startAccessingSecurityScopedResource()` を呼び出す必要があるかもしれません。
- アプリは、検索 ([`isEligibleForSearch`](https://developer.apple.com/documentation/foundation/nsuseractivity/iseligibleforsearch)) や予測 ([`isEligibleForPrediction`](https://developer.apple.com/documentation/foundation/nsuseractivity/iseligibleforprediction)) の対象となるものとして、アクティビティをマークでき、そのアクティビティを Spotlight や Siri の提案のそれぞれに公開します。
