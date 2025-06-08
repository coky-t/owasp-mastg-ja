---
masvs_v1_id:
- MSTG-AUTH-1
- MSTG-STORAGE-11
masvs_v2_id:
- MASVS-AUTH-2
platform: android
title: 認証情報確認のテスト (Testing Confirm Credentials)
masvs_v1_levels:
- L2
profiles: [L2]
---

## 概要

## 静的解析

アンロックされた鍵がアプリケーションフローの中で使用されていることを確認します。例えば、鍵はローカルストレージや、リモートエンドポイントから受信したメッセージを復号化するために使用される可能性があります。アプリケーションはユーザーが鍵をアンロックしたかどうかを単に確認しているだけであれば、そのアプリケーションはローカル認証のバイパスに対して脆弱となる可能性があります。

## 動的解析

ユーザーが正常に認証された後、鍵の使用が認可されている期間 (秒) を確認します。これは `setUserAuthenticationRequired` が使用されている場合にのみ必要です。
