---
masvs_category: MASVS-STORAGE
platform: android
title: アプリ通知 (App Notifications)
---

[通知](https://developer.android.com/guide/topics/ui/notifiers/notifications "Notifications Overview") をプライベートなものとみなすべきではないことを理解することが重要です。通知が Android システムで処理されると、システム全体にブロードキャストされ、[NotificationListenerService](https://developer.android.com/reference/kotlin/android/service/notification/NotificationListenerService "NotificationListenerService") を用いて実行しているアプリケーションはこれらの通知をリッスンして完全に受信し、必要に応じて処理できます。

[Joker](https://research.checkpoint.com/2020/new-joker-variant-hits-google-play-with-an-old-trick/ "Joker Malware") や [Alien](https://www.threatfabric.com/blogs/alien_the_story_of_cerberus_demise.html "Alien Malware") などの多くの既知のマルウェアサンプルがあります。これらは `NotificationListenerService` を悪用してデバイス上の通知をリッスンし、攻撃者が制御する C2 インフラストラクチャに送信します。一般的にこれはデバイス上に通知として現れる二要素認証 (2FA) コードをリッスンし、攻撃者に送信されます。ユーザーにとってより安全な代替手段は通知を生成しない 2FA アプリケーションを使用することです。

さらに Google Play ストアには、Android システム上のすべての通知をローカルにログ記録する、通知ログ記録機能を備えたアプリが多数あります。これは Android では通知が決してプライベートではなく、デバイス上の他のアプリからアクセスできることを示しています。

このため、すべての通知の使用については、悪意のあるアプリケーションによって使用される可能性のある機密情報や高リスク情報について検査する必要があります。
