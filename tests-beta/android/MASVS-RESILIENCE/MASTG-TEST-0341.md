---
platform: android
title: フック検出技法の実行時使用 (Runtime Use of Hook Detection Techniques)
id: MASTG-TEST-0341
type: [dynamic, hooks]
weakness: MASWE-0107
best-practices: [MASTG-BEST-0041]
profiles: [R]
knowledge: [MASTG-KNOW-0030, MASTG-KNOW-0032, MASTG-KNOW-0118]
---

## 概要

このテストは、アプリが実行時に計装やフックの試みを検出して対応するかどうかを検証します。たとえば、以下のメソッドが呼び出された際に即座に終了しない場合、問題となる可能性があります。

- [`AccountManager.getPassword()`](https://developer.android.com/reference/kotlin/android/accounts/AccountManager#getpassword), [`AccountManager.getAuthToken()`](https://developer.android.com/reference/kotlin/android/accounts/AccountManager#getauthtoken) がフックされている場合、認証トークン、OAuth トークン、セッションクレデンシャル、保存されているアカウントパスワードが抽出される可能性があります。
- [`KeyStore.getKey()`](https://developer.android.com/reference/kotlin/java/security/KeyStore#getkey), [`KeyStore.getCertificate()`](https://developer.android.com/reference/kotlin/java/security/KeyStore#getcertificate) がフックされている場合、暗号鍵と証明書が抽出される可能性があります。
- [`Cipher.doFinal()`](https://developer.android.com/reference/kotlin/javax/crypto/Cipher#dofinal) がフックされている場合、一時鍵/セッション鍵が抽出される可能性があります。
- [`SQLiteDatabase.rawQuery()`](https://developer.android.com/reference/kotlin/android/database/sqlite/SQLiteDatabase#rawquery), [`SQLiteDatabase.query()`](https://developer.android.com/reference/kotlin/android/database/sqlite/SQLiteDatabase#query), [`SQLiteDatabase.execSQL()`](https://developer.android.com/reference/kotlin/android/database/sqlite/SQLiteDatabase#execsql) がフックされている場合、データベースの内容が抽出される可能性があります。
- [`EncryptedSharedPreferences`](https://developer.android.com/reference/kotlin/androidx/security/crypto/EncryptedSharedPreferences) API がフックされている場合、暗号化されたデータが抽出される可能性があります。
- [`KeyGenParameterSpec.Builder.setUserAuthenticationRequired()`](https://developer.android.com/reference/kotlin/android/security/keystore/KeyGenParameterSpec.Builder#setuserauthenticationrequired) がフックされている場合、認証がバイパスされる可能性があります。
- 機密データを処理または返すその他の関数がフックされている。

> [!WARNING]
> このリストはあくまで例示であり、各アプリには独自の防御対応メカニズムを備えている可能性があります。

## 手順

1. [アプリのインストール (Installing Apps)](../../../techniques/android/MASTG-TECH-0005.md) を使用して、アプリをインストールします。
2. [メソッドフック (Method Hooking)](../../../techniques/android/MASTG-TECH-0043.md) を使用して、関連する API 呼び出しをフックします。
3. アプリを徹底的に動かして、できるだけ多くのフローをトリガーし、可能な限り機密データを入力します。

## 結果

出力には以下のいずれかを含む可能性があります。

- 期待されるフックコールバックデータ (例: 関数引数、戻り値)。
- セッション終了、スクリプトエラー、空の応答、または期待されるフックデータの不在。

## 評価

フックが正常に実行し、期待されるデータを返す場合、そのテストケースは不合格であり、アプリが実行時完全性検証を欠いていることを示しています。

アプリの防御的応答 (セッションが予期せず終了する、フックのコールバックが実行しない、プロセスが終了しないなど) によってフッキング試行が失敗する場合、そのテストケースは合格です。

> [!NOTE]
> テストケースが合格したとしても、アプリの防御的応答をバイパスできる可能性が依然としてあります。[リバースエンジニアリングツールの検出 (Detection of Reverse Engineering Tools)](../../../knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0030.md) と [MASTG-KNOW-0032 ランタイム完全性検証 (Runtime Integrity Verification)](../../../knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0032.md) では、そうした課題について説明しています。
