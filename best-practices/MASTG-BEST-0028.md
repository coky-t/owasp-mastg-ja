---
title: WebView キャッシュをクリーンアップする (WebViews Cache Cleanup)
alias: android-webviews-cache-cleanup
id: MASTG-BEST-0028
platform: android
---

Android WebView は、サーバーがブラウザにコンテンツをキャッシュするように指示する特定の `Cache-Control` ヘッダで応答すると、データをキャッシュします。WebView が機密データを処理する場合、WebView が不要となった後にもデバイス (ディスクや RAM) に残らないようにする必要があります。

機密データを含む API レスポンスで `Cache-Control: no-cache` などのヘッダを使用して、WebView にキャッシュしないように指示することにより、サーバーサイドのキャッシュ防止を優先します。

サーバーサイドのコントロールが不可能な場合、または補助的なコントロールとして、[`WebSettings.setCacheMode()`](https://developer.android.com/reference/android/webkit/WebSettings#setCacheMode(int)) で [`WebSettings.LOAD_NO_CACHE`](https://developer.android.com/reference/kotlin/android/webkit/WebSettings#LOAD_NO_CACHE:kotlin.Int) を明示的に設定するか、WebView の使用後 (WebView Activity の `onDestroy` ライフサイクル呼び出しなど) に [`WebView.clearCache(includeDiskFiles = true)`](https://developer.android.com/reference/android/webkit/WebView#clearCache(boolean)) で WebView キャッシュをクリアすることで、このリスクを軽減します。但し、この手法には二つの欠点があります。

1. 一つ目の欠点は、画像などのより大きなファイルなど、実際にキャッシュの恩恵を受ける非機密のアイテムを含め、すべてのキャッシュデータを無差別に削除することです。
2. 二つ目の欠点は、特にアプリプロセスが突然終了した場合、clear メソッドが必ず呼び出されるという保証がないことです。この場合、次回のアプリ起動時などに、事前のキャッシュクリアとアクティブクリアを評価する必要があります。

[WebView (WebViews)](../knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018.md) では、WebView で使用されるさまざまなストレージ領域について説明しています。
