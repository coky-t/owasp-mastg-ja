---
title: スクリーンキャプチャ防止 API への参照 (References to Screen Capturing Prevention APIs)
platform: android
id: MASTG-TEST-0291
type: [static]
profiles: [L2]
best-practices: [MASTG-BEST-0014]
weakness: MASWE-0055
---

## 概要

このテストは、アプリが Android のスクリーンキャプチャ防止 API を参照しているかどうかを検証します。Android では、開発者は [`FLAG_SECURE`](https://developer.android.com/security/fraud-prevention/activities#flag_secure) を使用して、スクリーンショットや安全でないディスプレイミラーリングを防止できます。設定すると、Android はスクリーンショットをブロックし、リモート画面共有を含む安全でないディスプレイへの表示からコンテンツを防ぎます。ユーザーがスクリーンショットを撮ろうとした場合、またはアプリがバックグラウンドに移動する際に、ブランクスクリーンを表示します。

開発者は一般的に [`addFlags()`](https://developer.android.com/reference/android/view/Window#addFlags(int)) または [`setFlags()`](https://developer.android.com/reference/android/view/Window#setFlags(int,int)) でフラグを適用します。よくある失敗モードとしては、すべての機密画面で `FLAG_SECURE` を設定していない、画面遷移時に [`clearFlags()`](https://developer.android.com/reference/android/view/Window#clearFlags(int)) や `setFlags()` を使用するなどでフラグをクリアしている、などがあります。

## 手順

1. 静的解析 ([Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md)) ツールを実行して、関連する API のインスタンスを識別します。

## 結果

出力には関連する API が使用されている場所のリストを含む可能性があります。

## 評価

関連する API が欠落している、または関連する API が機密データを表示するすべての UI コンポーネントに一貫して適用されていない場合、または十分な正当性がないままコードパスが保護をクリアする場合、このテストケースは不合格です。
