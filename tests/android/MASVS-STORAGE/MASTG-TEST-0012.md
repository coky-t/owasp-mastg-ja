---
masvs_v1_id:
- MSTG-STORAGE-11
masvs_v2_id:
- MASVS-STORAGE-1
platform: android
title: デバイスアクセスセキュリティポリシーのテスト (Testing the Device-Access-Security Policy)
masvs_v1_levels:
- L2
---

## 概要

機密情報を処理またはクエリするアプリは信頼できる安全な環境で実行する必要があります。この環境を作成するために、アプリはデバイスで以下のことをチェックできます。

- PIN またはパスワード保護されたデバイスのロック
- 最新の Android OS バージョン
- USB デバッグの有効化
- デバイスの暗号化
- デバイスのルート化 ("ルート検出のテスト" も参照)

## 静的解析

アプリが適用するデバイスアクセスセキュリティポリシーをテストするには、ポリシーの書面コピーが提供されなければなりません。ポリシーは利用可能なチェックとその実施を定義する必要があります。たとえば、あるチェックでは Android 6.0 (API レベル 23) 以降のバージョンでのみ実行され、Android バージョンが 6.0 未満の場合はアプリを閉じるか警告を表示することができます。

ポリシーを実装する関数のソースコードをチェックし、それをバイパスできるかどうかを判断します。

システム設定について [_Settings.Secure_](https://developer.android.com/reference/android/provider/Settings.Secure.html "Settings.Secure") をクエリすることで Android デバイスにチェックを実装できます。[_Device Administration API_](https://developer.android.com/guide/topics/admin/device-admin.html "Device Administration API") はパスワードポリシーとデバイス暗号化を強制できるアプリケーションを作成するためのテクニックを提供します。

## 動的解析

動的解析はアプリによって強制されるチェックとその期待される動作に依存します。そのチェックをバイパスできる可能性がある場合は、それを検証しなければなりません。
