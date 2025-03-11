---
platform: android
title: WebView におけるコンテンツプロバイダアクセスへの参照 (References to Content Provider Access in WebViews)
alias: references-to-content-provider-access-in-webviews
id: MASTG-TEST-0250
apis: [WebView, ContentProvider, allowContentAccess]
type: [static]
weakness: MASWE-0069
best-practices: []
status: draft
note: このテストでは WebView におけるコンテンツプロバイダアクセスへの参照をチェックします。これはデフォルトで有効になっており、`WebSettings` クラスの `setAllowContentAccess` メソッドを使用して無効にできます。不適切に構成すると、不正なファイルアクセスやデータ流出などのセキュリティリスクを引き起こす可能性があります。
---
