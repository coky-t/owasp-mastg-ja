---
platform: android
title: 機密データをクリーンアップしない WebView (WebViews Not Cleaning Up Sensitive Data)
id: MASTG-TEST-0320
type: [dynamic]
weakness: MASWE-0118
profiles: [L1, L2]
best-practices: [MASTG-BEST-0028]
knowledge: [MASTG-KNOW-0018]
prerequisites:
- identify-sensitive-data
---

## 概要

このテストはアプリが WebView で使用される機密データをクリーンアップするかどうかを検証します。アプリは WebView での特定のストレージ領域を有効にしておきながら、適切にクリーンアップせず、機密データがデバイス上に必要以上に長く保存されることにつながる可能性があります。たとえば、以下のとおりです。

- 以下の場合に [`WebView.clearCache(includeDiskFiles = true)`](https://developer.android.com/reference/android/webkit/WebView#clearCache(boolean)) を呼び出していない:
    - `WebSettings.setAppCacheEnabled()` が有効になっている。
    - または [`WebSettings.setCacheMode()`](https://developer.android.com/reference/android/webkit/WebSettings#setCacheMode(int)) が [`WebSettings.LOAD_NO_CACHE`](https://developer.android.com/reference/kotlin/android/webkit/WebSettings#LOAD_NO_CACHE:kotlin.Int) 以外の値である。
- 以下の場合に [`WebStorage.deleteAllData()`](https://developer.android.com/reference/android/webkit/WebStorage#deleteAllData()) を呼び出していない:
    - [`WebSettings.setDomStorageEnabled`](https://developer.android.com/reference/android/webkit/WebSettings#setDomStorageEnabled(boolean)) が有効になっている。
- 以下の場合に [`WebStorage.deleteAllData()`](https://developer.android.com/reference/android/webkit/WebStorage#deleteAllData()) を呼び出していない:
    - [`WebSettings.setDatabaseEnabled()`](https://developer.android.com/reference/android/webkit/WebSettings#setDatabaseEnabled(boolean)) が有効になっている。
- 以下の場合に [`CookieManager.removeAllCookies(ValueCallback<Boolean> ...)`](https://developer.android.com/reference/android/webkit/CookieManager#removeAllCookies(android.webkit.ValueCallback%3Cjava.lang.Boolean%3E)) を呼び出していない:
    - [`CookieManager.setAcceptCookie()`](https://developer.android.com/reference/android/webkit/CookieManager#setAcceptCookie(boolean)) が明示的に `false` に設定されていない (デフォルトでは `true` に設定されている).

このテストは動的解析を使用して、関連する API 呼び出しとファイルシステム操作を監視します。アプリがこれらの API を直接使用しているかどうかに関係なく、WebView はコンテンツをレンダリングする際に内部的にそれらを使用する可能性があります (例: `localStorage` を使用する JavaScript コード)。そのため、`open`, `openat`, `opendir`, `unlinkat` などの API の呼び出しをトレースすることで、WebView ストレージディレクトリ内のファイル操作を特定できます。

## 手順

1. デバイスにアプリをインストールします ([アプリのインストール (Installing Apps)](../../../techniques/ios/MASTG-TECH-0056.md))。
2. [メソッドトレース (Method Tracing)](../../../techniques/android/MASTG-TECH-0033.md) を使用して、ストレージの有効化とクリーンアップについて WebView API をターゲットにします。
3. アプリを開きます。
4. アプリを広範に使用して、関連するすべての WebView がカバーされ、機密データがロードされることを確認します。クリーンアップする必要がある機密データのリストを保管しておきます。
5. アプリを閉じます。
6. [ホストとデバイス間のデータ転送 (Host-Device Data Transfer)](../../../techniques/android/MASTG-TECH-0002.md) を使用して `/data/data/<app_package>/app_webview/` ディレクトリの内容を取得するか、単純にそのディレクトリ内で WebView で使用されている機密データを検索します。

## 結果

出力には以下を含む可能性があります。

1. 使用している WebView ストレージ有効化 API のリスト。
2. 使用している WebView ストレージクリーンアップ API のリスト。
3. クリーンアップする必要がある機密データのリスト。
4. アプリを閉じた後、WebView で使用された機密データについて `/data/data/<app_package>/app_webview/` ディレクトリの内容を検索した結果。

## 評価

アプリが閉じられた後にも依然として `/data/data/<app_package>/app_webview/` ディレクトリに機密データがある場合、そのテストケースは不合格です。これはアプリが WebView の使用後に関連するクリーンアップ API を呼び出していないことに起因する可能性があります。

WebView で使用されるすべての機密データが関連する API を使用して適切にクリーンアップされ、アプリを閉じた後に `/data/data/<app_package>/app_webview/` ディレクトリに機密データが残っていない場合、そのテストは合格です。

### !!! 注意
有効になっているストレージ領域に対して適切なクリーンアップ API が呼び出されたかどうかを判断することが困難なことがあります。[WebView (WebViews)](../../../knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018.md) では、WebView により使用されるストレージ領域と、それらのクリーンアップを評価する際の課題について説明しています。

**追加ガイダンス**:

実行時にさらに詳細なイントロスペクションを必要とする場合、WebView ストレージディレクトリ内のファイルシステム操作のトレースを追加してテストを再実行します。[WebView でのファイルシステム操作の監視 (Monitor File System Operations in WebViews)](../../../techniques/android/MASTG-TECH-0143.md) を参照してください。
