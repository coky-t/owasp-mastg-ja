---
masvs_category: MASVS-STORAGE
platform: ios
title: スクリーンショット (Screenshots)
---

製造業者は、アプリケーションの起動時や終了時にデバイスユーザーに美的で心地よい効果を提供したいと考え、アプリケーションがバックグラウンドに移行する際にスクリーンショットを保存するという概念を導入しました。この機能は、スクリーンショット (電子メールや企業文書などの機密情報を表示することがあります) がローカルストレージに書き込まれ、サンドボックスをバイパスするエクスプロイトを備えた不正アプリケーションやデバイスを盗んだ人物により復元される可能性があるため、セキュリティリスクをもたらす可能性があります。

スクリーンショットはアプリのコンテナ内の `/var/mobile/Containers/Data/Application/$APP_ID/Library/SplashBoard/Snapshots/sceneID:$APP_NAME-default/` に保存されます。
アプリがバックグラウンド状態に入るたびに上書きされます。

システムは [`applicationDidEnterBackground`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/applicationdidenterbackground(_:)) が完了した後にスクリーンショットを取得するために、スクリーンのコンテンツの上にオーバーレイを表示するのが一般的です。アプリがフォアグラウンドに戻ると、[`applicationWillEnterForeground`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/applicationwillenterforeground(_:)) が呼び出されます。

詳細については ["Prepare your UI for the app snapshot"](https://developer.apple.com/documentation/uikit/preparing-your-ui-to-run-in-the-background#Prepare-your-UI-for-the-app-snapshot) をご覧ください。
