---
title: badssl
platform: network
source: https://github.com/chromium/badssl.com
---

badssl は Chromium プロジェクトが管理するウェブサイトで、セキュリティ実装をテストするためのさまざまな SSL/TLS 証明書構成を提供しています。さまざまな証明書の問題と構成を持つ包括的なテストサブドメインを提供しており、開発者やセキュリティテスト担当者が SSL/TLS 証明書バリデーションをどのように処理するかを検証するのに役立ちます。

このツールは以下のような一般的な SSL/TLS の脆弱性や設定ミスに対するテストケースを提供します。

- 自己署名証明書 (`self-signed.badssl.com`)
- 期限切れの証明書 (`expired.badssl.com`)
- ホスト名に誤りのある証明書 (`wrong.host.badssl.com`)
- 信頼できないルート証明書 (`untrusted-root.badssl.com`)
- 混合コンテンツシナリオ (`mixed.badssl.com`)
- 脆弱な暗号スイート (`rc4.badssl.com`, `dh512.badssl.com`)
- HSTS テスト (`hsts.badssl.com`)
- 証明書の透明性に関する問題 (`no-sct.badssl.com`)

これにより、badssl.com はモバイルアプリケーションの SSL/TLS 証明書バリデーションロジックをテストし、無効な証明書を拒否し、さまざまなセキュリティシナリオを正しく処理することを確認するために特に役立ちます。
