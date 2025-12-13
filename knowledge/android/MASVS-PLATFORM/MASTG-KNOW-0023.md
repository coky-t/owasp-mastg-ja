---
masvs_category: MASVS-PLATFORM
platform: android
title: 強制アップデート (Enforced Updating)
---

Android 5.0 (API レベル 21) 以降では、Play Core Library と併用することで、アプリはアップデートを強制できます。このメカニズムは `AppUpdateManager` を使用することに基づいています。それ以前は、Google Play ストアへの http 呼び出しなどの他のメカニズムが使用されており、Play ストアの API が変更される可能性があるため、信頼性がありません。代わりに、Firebase を使用して、強制アップデートの可能性をチェックすることもできます (こちらの [ブログ](https://medium.com/@sembozdemir/force-your-users-to-update-your-app-with-using-firebase-33f1e0bcec5a "Force users to update the app using Firebase") をご覧ください)。
強制アップデートは、公開鍵のピン留め (詳細についてはネットワーク通信のテストを参照) において、証明書/公開鍵のローテーションによりピンをリフレッシュする必要がある場合に非常に役立ちます。さらに、強制アップデートによって脆弱性を簡単にパッチ適用できます。

アプリケーションの新しいバージョンは、アプリが通信するバックエンドに存在するセキュリティ問題を修正しないことに注意してください。アプリがそれと通信できないようにするだけでは十分ではない可能性があります。適切な API ライフサイクル管理がここでの鍵となります。
同様に、ユーザーがアップデートを強制されない場合、アプリの古いバージョンを API に対してテストしたり、適切な API バージョン管理を使用することを忘れないでください。
