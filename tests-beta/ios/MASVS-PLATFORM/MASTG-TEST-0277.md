---
platform: ios
title: 実行時の iOS の一般的なペーストボード内の機密データ (Sensitive Data in the iOS General Pasteboard at Runtime)
id: MASTG-TEST-0277
type: [dynamic]
weakness: MASWE-0053
threat: [app]
prerequisites:
- identify-sensitive-data
---

## 概要

このテストは [iOS の一般的なペーストボードの使用 (Use of the iOS General Pasteboard)](MASTG-TEST-0276.md) と対をなす動的テストです。

このケースでは、実行時に [ペーストボード](../../../Document/0x06h-Testing-Platform-Interaction.md#pasteboard) に機密データが書き込まれていないか監視します。テストを実行している間にアプリを実行していて、ペーストボードが変更される必要があるため、これを検出するのは困難となる可能性があることに注意してください。テスト実行中にパスワードや個人情報などの機密データをアプリに手作業で入力することで、ペーストボードをトリガーできます。または、ユーザー入力をシミュレートしたり、ペーストボードを直接変更するスクリプトを使用して、自動的にトリガーすることもできます。

## 手順

1. [ペーストボードの監視 (Monitoring the Pasteboard)](../../../techniques/ios/MASTG-TECH-0134.md) を使用して、ペーストボードに機密データがないか監視します。
2. アプリを実行し、パスワードや個人情報のコピーなど、機密データをペーストボードに書き込む可能性のあるアクションを実行します。

## 結果

出力にはテスト中に書き込まれたペーストボードアイテムのリストを含む可能性があります。

## 評価

特に一般的なペーストボードへの書き込み操作時に機密データがトレースされた場合、そのテストは不合格です。
