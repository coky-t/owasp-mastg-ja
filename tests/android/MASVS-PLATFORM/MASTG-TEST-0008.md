---
masvs_v1_id:
- MSTG-STORAGE-7
masvs_v2_id:
- MASVS-PLATFORM-3
platform: android
title: ユーザーインタフェースを介した機密データの漏洩のチェック (Checking for Sensitive Data Disclosure Through the User Interface)
masvs_v1_levels:
- L1
- L2
profiles: [L2]
status: deprecated
covered_by: [MASTG-TEST-0316]
deprecation_note: New version available in MASTG V2
---

## 概要

## 静的解析

このような情報を表示したり、入力として受け取るすべての UI コンポーネントを注意深くレビューします。機密情報の痕跡を探し、それをマスクするか完全に削除する必要があるか評価します。

### テキストフィールド

アプリケーションが機密性の高いユーザー入力をマスクしていることを確認するには、`EditText` の定義で以下の属性を確認します。

```xml
android:inputType="textPassword"
```

この設定では、テキストフィールドに (入力文字の代わりに) ドットを表示し、アプリがパスワードや PIN をユーザーインタフェイスに漏洩するのを防ぎます。

### アプリ通知

アプリケーションを静的に評価する際、何らかの形式の通知管理を示す可能性のある `NotificationManager` クラスの使用箇所を探すことをお勧めします。このクラスが使用されている場合、次のステップはアプリケーションがどのように [通知を生成している](https://developer.android.com/training/notify-user/build-notification#SimpleNotification "Create a Notification") のかを理解することです。

以下の動的解析セクションでこれらのコードの場所に入力すると、アプリケーション内のどこで通知が動的に生成されるかがわかります。

## 動的解析

アプリケーションが機密情報をユーザーインタフェースに漏洩しているかどうかを判断するには、アプリケーションを実行し、情報を漏洩している可能性のあるコンポーネントを特定します。

### テキストフィールド

たとえば、入力をアスタリスクやドットに置き換えることによって情報がマスクされている場合、アプリはユーザーインタフェースにデータを漏洩していません。

### アプリ通知

通知の使用箇所を特定するには、アプリケーション全体とその利用可能な機能を実行して、通知をトリガーする方法を探します。特定の通知をトリガーするにはアプリケーションの外部でアクションを実行する必要があるかもしれないことを考慮します。

アプリケーションの実行時に、[`NotificationCompat.Builder`](https://developer.android.com/reference/androidx/core/app/NotificationCompat.Builder) の `setContentTitle` や `setContentText` など、通知の作成に関連するすべての呼び出しのトレースを開始します。最後にトレースを観察し、機密情報が含まれているかどうかを評価します。
