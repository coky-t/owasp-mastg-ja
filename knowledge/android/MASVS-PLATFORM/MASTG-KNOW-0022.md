---
masvs_category: MASVS-PLATFORM
platform: android
title: オーバーレイ攻撃 (Overlay Attacks)
---

スクリーンオーバーレイ攻撃は悪意のあるアプリケーションがフォアグラウンドで正常に動作している別のアプリケーションの上に自信を重ねることで発生します。悪意のあるアプリは元のアプリの外観と操作感や Android システム UI を模倣した UI 要素を作成するかもしれません。その狙いは、一般的にユーザーに正規のアプリとやり取りし続けていると信じ込ませ、権限の昇格 (何らかのパーミッションを付与するなど)、ステルスフィッシング、ユーザーのタップやキーストロークをキャプチャするなどを試みることです。

以下のようなさまざまな Android バージョンに影響を及ぼす攻撃がいくつかあります。

- [**タップジャッキング**](https://medium.com/devknoxio/what-is-tapjacking-in-android-and-how-to-prevent-it-50140e57bf44 "What is Tapjacking in Android and How to Prevent It") (Android 6.0 (API レベル 23) 以下) は Android のスクリーンオーバーレイ機能を悪用してタップをリッスンし、基盤となるアクティビティに渡される情報を傍受します。
- [**Cloak & Dagger**](https://cloak-and-dagger.org/ "Cloak & Dagger") 攻撃は Android 5.0 (API レベル 21) から Android 7.1 (API レベル 25) をターゲットとするアプリに影響を及ぼします。それらは `SYSTEM_ALERT_WINDOW` ("draw on top") および `BIND_ACCESSIBILITY_SERVICE` ("a11y") パーミッションの一方または両方を悪用します。Play ストアからアプリをインストールした場合、ユーザーは明示的に付与する必要はなく、通知もされません。
- [**トーストオーバーレイ**](https://unit42.paloaltonetworks.com/unit42-android-toast-overlay-attack-cloak-and-dagger-with-no-permissions/ "Android Toast Overlay Attack: Cloak and Dagger with No Permissions") は Cloak & Dagger に非常に似ていますが、ユーザーによる特定の Android パーミッションの付与を必要としません。これは Android 8.0 (API レベル 26) において CVE-2017-0752 で解決されました。

通常、この種の攻撃は特定の脆弱性や設計上の問題が存在する Android システムのバージョンに起因します。これは、アプリが安全な Android バージョン (API レベル) をターゲットとするようにアップグレードされない限り、防ぐことは困難であり、事実上不可能となることがよくあります。

長年にわたり、MazorBot, BankBot, MysteryBot などの多くの既知のマルウェアが Android のスクリーンオーバーレイ機能を悪用し、ビジネスクリティカルなアプリケーション、特に銀行業界のもの、をターゲットにしてきました。この [ブログ](https://www.infosecurity-magazine.com/opinions/overlay-attacks-safeguard-mobile/ "Dealing with Overlay Attacks: Adopting Built-in Security to Safeguard Mobile Experience") ではこの種のマルウェアについて詳しく説明しています。
