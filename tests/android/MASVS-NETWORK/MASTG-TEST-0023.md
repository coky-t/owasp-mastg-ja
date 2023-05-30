---
masvs_v1_id:
- MSTG-NETWORK-6
masvs_v2_id:
- MASVS-NETWORK-1
platform: android
title: セキュリティプロバイダのテスト (Testing the Security Provider)
masvs_v1_levels:
- L2
---

## 概要

## 静的解析

Android SDK をベースとするアプリケーションは GooglePlayServices に依存する必要があります。例えば、gradle ビルドファイルには、dependencies ブロックに `compile 'com.google.android.gms:play-services-gcm:x.x.x'` があります。`ProviderInstaller` クラスは `installIfNeeded` または `installIfNeededAsync` のどちらかで呼び出されていることを確認する必要があります。`ProviderInstaller` はできるだけ早期にアプリケーションのコンポーネントにより呼び出される必要があります。これらのメソッドによりスローされる例外は正しく捕捉および処理されるべきです。アプリケーションがそのセキュリティプロバイダにパッチを適用することができない場合、そのセキュアではない状態の API を通知するかユーザー操作を制限します (すべての HTTPS トラフィックがこの状況ではより危険であるとみなすべきであるため) 。

ソースコードにアクセスできる場合は、セキュリティプロバイダのアップデートに関連する例外をアプリが適切に処理するかどうか、および、アプリケーションがパッチされていないセキュリティプロバイダで動作している場合にバックエンドに報告されるかどうかを確認します。 Android 開発者ドキュメントでは [SSL エクスプロイトを防ぐためにセキュリティプロバイダをアップデートする方法](https://developer.android.com/training/articles/security-gms-provider.html "Updating Your Security Provider to Protect Against SSL Exploits") を示すさまざまな例を提供しています。

最後に、NDK ベースのアプリケーションは SSL/TLS 機能を提供する最新の正しくパッチ適用されたライブラリにのみバインドすることを確認します。

## 動的解析

ソースコードがある場合:

- デバッグモードでアプリケーションを実行し、アプリが最初にエンドポイントに接続するブレークポイントを作成します。
- ハイライトされたコードを右クリックし、`Evaluate Expression` を選択します。
- `Security.getProviders()` と入力し Enter キーを押します。
- プロバイダをチェックし `GmsCore_OpenSSL` を探してみます。これは新たにトップにリストアップされたプロバイダになるはずです。

ソースコードがない場合:

- Xposed を使用して `java.security` パッケージにフックし、`java.security.Security` の `getProviders` メソッド (引数なし) にフックします。戻り値は `Provider` の配列になります。
- 最初のプロバイダが `GmsCore_OpenSSL` であるかどうかを判断します。
