---
platform: android
title: 通知を介して露出する機密データ (Sensitive Data Exposed via Notifications)
id: MASTG-TEST-0315
apis: [NotificationManager]
type: [static]
weakness: MASWE-0054
prerequisites:
- identify-sensitive-data
profiles: [L2]
best-practices: [MASTG-BEST-0027]
knowledge: [MASTG-KNOW-0054]
---

## 概要

このテストはアプリが通知を正しく処理することを検証します。個人を識別できる情報 (PII)、ワンタイムパスワード (OTP)、健康や金融の詳細などのその他の機密データのような、機密情報がさらされていないことを確認します。

Android 13 以降では、API レベル 33 以上をターゲットとするアプリは通知を送信するためにランタイムパーミッション [`POST_NOTIFICATIONS`](https://developer.android.com/reference/android/Manifest.permission#POST_NOTIFICATIONS) をリクエストする必要があります。API レベル 33 未満では、このパーミッションは必要ありません。テスト目的では、アプリが実行可能な最低限の Android バージョンを示す、アプリの `minSdkVersion` の値を考慮します。

通知は [`Notification.Builder`](https://developer.android.com/reference/android/app/Notification.Builder) または [`NotificationCompat.Builder`](https://developer.android.com/reference/androidx/core/app/NotificationCompat.Builder) の [`setContentTitle`](https://developer.android.com/reference/android/app/Notification.Builder#setContentTitle(java.lang.CharSequence)) メソッドと [`setContentText`](https://developer.android.com/reference/android/app/Notification.Builder#setContentText(java.lang.CharSequence)) メソッドを使用して作成できます。

通知の使用では、ショルダーサーフィンや、他人とデバイスを共有している場合などに、誤って開示される可能性のある機密情報をさらしてはいけません。

## 手順

1. [Android アプリのリバースエンジニアリング (Reverse Engineering Android Apps)](../../../techniques/android/MASTG-TECH-0013.md) を使用して、アプリをリバースエンジニアします。
2. [AndroidManifest から情報の取得 (Obtaining Information from the AndroidManifest)](../../../techniques/android/MASTG-TECH-0117.md) を使用して、AndroidManifest.xml ファイルを取得します。
3. [Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md) を使用して、AndroidManifest.xml ファイルの `POST_NOTIFICATIONS` パーミッションと `minSdkVersion` の宣言を探します。
4. [Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md) を使用して、アプリのソースコードの `NotificationCompat.Builder`, `setContentTitle`, `setContentText` などの通知 API への参照を探します。

## 結果

出力には以下を含む可能性があります。

- `POST_NOTIFICATIONS` パーミッション (宣言されている場合)、
- `minSdkVersion` の値、
- 通知 API が使用される場所のリスト。

## 評価

アプリが通知で機密データを露出し、かつ以下のいずれかの場合、そのテストケースは不合格です。

- `minSdkVersion` が `33` 以上で、`POST_NOTIFICATIONS` パーミッションがマニフェストファイルに宣言されている、または
- `minSdkVersion` が `32` 以下 (`POST_NOTIFICATIONS` パーミッションが宣言されているかどうかに関わらず) の場合

**なぜ `minSdkVersion` であり、`targetSdkVersion` ではないのか？**: `minSdkVersion` を使用すると、アプリが動作できる **最も安全性の低い環境** をテストで考慮することを確保し、これが実際の露出リスクを決定します。

`targetSdkVersion` は、新しい Android バージョンでのアプリの動作と、システムが新しいプラットフォーム制限を適用する方法にのみ影響します。古い Android バージョンの動作は変更しません。結果として、`targetSdkVersion` は高いが `minSdkVersion` が低いアプリは、古いバージョンのセキュリティ保証 (またはその欠如) に対して評価する必要があります。
