---
title: アプリのバックグラウンド時のスクリーンショットでの機密コンテンツ露出の実行時検証 (Runtime Verification of Sensitive Content Exposure in Screenshots During App Backgrounding)
platform: android
id: MASTG-TEST-0289
type: [dynamic, manual]
profiles: [L2]
best-practices: [MASTG-BEST-0014]
weakness: MASWE-0055
prerequisites:
- identify-sensitive-screens
---

## 概要

このテストは、アプリがバックグラウンドに移動するときに、画面から機密コンテンツが隠れていることを検証します。アプリ UI がバックグラウンドに移動するときに、Android はそのタスクスクリーンショットをキャプチャするため、これは重要です。このスクリーンショットは [最近の画面](https://developer.android.com/guide/components/activities/recents) や画面遷移に使用され、アプリが機密コンテンツを保護していない場合には露出する可能性があります。

## 手順

1. 機密として識別される各画面になるまでアプリを動かします。これらの画面ごとに、アプリをバックグラウンドに移動 (たとえば **ホーム** を押したり、**最近の画面** を開いて終了するなど) し、次の画面に進みます。
2. 完了したら、[ホストとデバイス間のデータ転送 (Host-Device Data Transfer)](../../../techniques/android/MASTG-TECH-0002.md) を使用して、システムによって撮影されたスクリーンショットをラップトップにコピーし、さらに解析します。システムはスクリーンショットをコンテナ `/data/system_ce/0/snapshots` または `/data/system` に保存します。

## 結果

出力にはアプリがバックグラウンド状態に入ったときにキャッシュされたスクリーンショットのコレクションを含む可能性があります。

## 評価

いずれかのスクリーンショットが保護される必要がある機密データを表示している場合、そのテストケースは不合格です。
