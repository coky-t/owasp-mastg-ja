---
title: アプリのバックグラウンド時のスクリーンショットでの機密コンテンツ露出の実行時検証 (Runtime Verification of Sensitive Content Exposure in Screenshots During App Backgrounding)
platform: ios
id: MASTG-TEST-0290
type: [dynamic, manual]
profiles: [L2]
weakness: MASWE-0055
prerequisites:
- identify-sensitive-screens
---

## 概要

このテストは、アプリがバックグラウンドに移動するときに、画面から機密コンテンツが隠れていることを検証します。アプリ UI がバックグラウンドに遷移するときに、iOS はそのスクリーンショットをキャプチャするため、これは重要です。このスクリーンショットは [アプリスイッチャー](https://support.apple.com/guide/iphone/switch-between-open-apps-iph1a1f981ad/ios) や画面遷移に使用され、アプリが機密コンテンツを保護していない場合には露出する可能性があります。

## 手順

1. 機密として識別される各画面になるまでアプリを動かします。これらの画面ごとに、アプリをバックグラウンドに移動 (たとえば **ホーム** を押したり、**アプリスイッチャー** を開いて終了するなど) し、次の画面に続けます。
2. 完了したら、[ホストとデバイス間のデータ転送 (Host-Device Data Transfer)](../../../techniques/ios/MASTG-TECH-0053.md) を使用して、システムによって撮影されたスクリーンショットを解析ワークステーションにコピーします。システムはそれらを `/var/mobile/Containers/Data/Application/<APP_ID>/Library/SplashBoard/Snapshots/sceneID:<APP_NAME>-default/` に保存します。正確なパスと構造は iOS のバージョンによって異なる可能性があることに注意してください。

## 結果

出力にはアプリがバックグラウンド状態に入ったときにキャッシュされたスクリーンショットのコレクションを含む可能性があります。

## 評価

いずれかのスクリーンショットが保護される必要がある機密データを表示している場合、そのテストケースは不合格です。
