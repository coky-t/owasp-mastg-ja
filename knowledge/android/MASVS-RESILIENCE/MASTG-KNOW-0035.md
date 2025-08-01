---
masvs_category: MASVS-RESILIENCE
platform: android
title: Google Play Integrity API
---

Google は Android 4.4 (レベル 19) 以降の Android 上のアプリとゲームのセキュリティと完全性を向上させるために [Google Play Integrity API](https://developer.android.com/google/play/integrity/overview "Google Play Integrity API") を開始しました。以前の公式 API [SafetyNet](https://developer.android.com/training/safetynet) は Google がプラットフォームに求めるすべてのセキュリティニーズをカバーしてはいなかったため、Play Integrity は以前の公式 API の基本機能に追加機能を統合して開発されました。この変更は危険で人を欺くやりとりからユーザーを保護することを目的としています。

**Google Play Integrity はセーフガードを提供します:**

- 純正 Android デバイスの検証: アプリケーションが正規の Android デバイス上で動作していることを検証します。
- ユーザーライセンスの検証: アプリケーションやゲームが Google Play ストアを通じてインストールまたは購入されたかどうかを示します。
- 改変なしバイナリの検証: アプリケーションが Google Play によって認識されているオリジナルのバイナリと相関があるかどうかを判断します。

API はセキュリティチームが判断を下すのに役立つ四つのマクロカテゴリ情報を提供します。これらのカテゴリは以下のとおりです。

1. **リクエストの詳細 (Request Details)**: このセクションでは、完全性チェックをリクエストしたアプリパッケージに関する詳細が取得されます。これにはそのフォーマット (com.example.myapp など)、リクエストと完全性証明書をリンクするために開発者が提供した Base64 エンコードされた ID、リクエストの実行時間 (ミリ秒) を含みます。

2. **アプリの完全性 (App Integrity)**: このセクションでは、アプリのインストール元が信頼できる (Play ストア経由) か不明/疑わしいかを示す検証結果 (命名された判定) など、アプリの完全性についての情報を提供します。インストール元が安全であると考えられる場合、アプリバージョンも表示されます。

3. **アカウントの詳細 (Account Details)**: このカテゴリでは、アプリのライセンスステータスに関する情報を提供します。この結果は `LICENSED`、`UNLICENSED`、`UNEVALUATED` になります。`LICENSED` はユーザーが Google Play ストアでアプリを購入またはインストールされたことを示します。`UNLICENSED` はユーザーがアプリを所有していないか、Google Play ストアを通じてアプリを取得していないことを意味します。`UNEVALUATED` は必要な要件が欠落しているため、ライセンスの詳細を評価できないことを意味します。つまり、デバイスが十分に信頼できないか、インストールされているアプリのバージョンが Google Play ストアによって認識されていない可能性があります。

4. **デバイスの完全性 (Device Integrity)**: このセクションでは、アプリが動作している Android 環境の真正性を検証する情報を示します。

- `MEETS_DEVICE_INTEGRITY`: アプリは Google Play サービスを搭載した Android デバイス上にあり、システム完全性チェックと互換性要件に合格しています。
- `MEETS_BASIC_INTEGRITY`: アプリは、Google Play サービスを実行することが承認されていない可能性があるものの基本的な完全性チェックに合格するデバイス上にあります。認識されていない Android バージョン、アンロックされたブートローダー、製造業者証明書の欠落が原因の可能性があります。
- `MEETS_STRONG_INTEGRITY`: アプリは Google Play サービスを搭載したデバイス上にあり、ハードウェアで保護されたブートなどの機能により堅牢なシステム完全性を確保しています。
- `MEETS_VIRTUAL_INTEGRITY`: アプリは Google Play サービスを搭載したエミュレータで動作しており、システム完全性チェックに合格し、Android 互換性要件を満たしています。

**API エラー:**

API は `APP_NOT_INSTALLED` や `APP_UID_MISMATCH` などのローカルエラーを返すことがあり、これは詐欺の試みや攻撃を示す可能性があります。さらに、Google Play サービスや Play Store が古い場合もエラーの原因となることがあるため、これらの状況をチェックして適切な完全性検証機能を確保し、環境が意図的に攻撃用に設定されていないことを確認することが重要です。詳細は [公式ページ](https://developer.android.com/google/play/integrity/error-codes) をご覧ください。

**ベストプラクティス:**

1. より広範なセキュリティ戦略の一環として Play Integrity を使用します。入力データバリデーション、ユーザー認証、不正防止などの追加のセキュリティ対策で補完します。
2. Play Protect API へのクエリを最小限に抑え、デバイスリソースへの影響を軽減します。たとえば、デバイスの完全性検証が必要な場合にのみ API を使用します。

3. 完全性検証リクエストに `NONCE` を含めます。アプリまたはサーバーが生成するこの乱数値は、サードパーティによる改竄がなく、レスポンスが元のリクエストと一致することを検証サーバーが確認するのに役立ちます。

**制限事項:**
Google Play Services Integrity Verification API リクエストのデフォルトの日ごとの制限は 10,000 リクエスト/日 です。それ以上を必要とするアプリケーションは Google に連絡して上限を増やすようリクエストしなければなりません。

**リクエスト例:**

```json
{
   "requestDetails": {
     "requestPackageName": "com.example.your.package",
     "timestampMillis": "1666025823025",
     "nonce": "kx7QEkGebwQfBalJ4...Xwjhak7o3uHDDQTTqI"
   },
   "appIntegrity": {
     "appRecognitionVerdict": "UNRECOGNIZED_VERSION",
     "packageName": "com.example.your.package",
     "certificateSha256Digest": [
       "vNsB0...ww1U"
     ],
     "versionCode": "1"
   },
   "deviceIntegrity": {
     "deviceRecognitionVerdict": [
       "MEETS_DEVICE_INTEGRITY"
     ]
   },
   "accountDetails": {
     "appLicensingVerdict": "UNEVALUATED"
   }
 }
```
