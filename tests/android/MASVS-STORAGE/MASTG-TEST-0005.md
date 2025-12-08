---
masvs_v1_id:
- MSTG-STORAGE-4
masvs_v2_id:
- MASVS-STORAGE-2
platform: android
title: 機密データが通知を介してサードパーティと共有されるかどうかの判定 (Determining Whether Sensitive Data Is Shared with Third Parties via Notifications)
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
status: deprecated
covered_by: [MASTG-TEST-0315]
deprecation_note: New version available in MASTG V2
---

## 概要

## 静的解析

何らかの形式の通知管理を示す可能性のある `NotificationManager` クラスの使用箇所を探します。このクラスが使用されている場合、次のステップはアプリケーションがどのように [通知を生成している](https://developer.android.com/training/notify-user/build-notification#SimpleNotification "Create a Notification") のか、およびどのデータが表示されるのかを理解することです。

## 動的解析

アプリケーションを実行し、[`NotificationCompat.Builder`](https://developer.android.com/reference/androidx/core/app/NotificationCompat.Builder) の `setContentTitle` や `setContentText` など、通知の作成に関連する関数のすべての呼び出しのトレースを開始します。最後にトレースを観察し、他のアプリが盗聴する可能性がある機密情報が含まれているかどうかを評価します。
