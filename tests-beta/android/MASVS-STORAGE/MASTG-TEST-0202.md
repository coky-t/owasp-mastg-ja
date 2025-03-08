---
platform: android
title: 外部ストレージにアクセスするための API とパーミッションへの参照 (References to APIs and Permissions for Accessing External Storage)
id: MASTG-TEST-0202
apis: [Environment#getExternalStoragePublicDirectory, Environment#getExternalStorageDirectory, Environment#getExternalFilesDir, Environment#getExternalCacheDir, MediaStore, WRITE_EXTERNAL_STORAGE, MANAGE_EXTERNAL_STORAGE]
type: [static]
weakness: MASWE-0007
---

## 概要

このテストでは静的解析を使用して、[外部ストレージ API](../../../0x05d-Testing-Data-Storage.md/#external-storage-apis) や [`MediaStore` API](../../../0x05d-Testing-Data-Storage.md/#mediastore-api) など、他のアプリと共有される場所にアプリが書き込むことを許可する API の使用 ([機密データについてのローカルストレージのテスト (Testing Local Storage for Sensitive Data)](../../../tests/android/MASVS-STORAGE/MASTG-TEST-0001.md)) や、[関連する Android マニフェストのストレージ関連パーミッション](../../../0x05d-Testing-Data-Storage.md/#manifest-permissions) を探します。

この静的テストは、アプリが共有ストレージにデータを書き込むすべてのコードの場所を特定するのに最適です。しかし、実際に書き込まれるデータや、場合によっては、データが書き込まれるデバイスストレージ内の実際のパスも提供しません。そのため、このテストを動的なアプローチを採る他のテストと組み合わせることをお勧めします。これは共有ストレージに書き込まれるデータのより完全なビューを提供することでしょう。

## 手順

1. アプリをリバースエンジニアします ([Java コードの逆コンパイル (Decompiling Java Code)](../../../techniques/android/MASTG-TECH-0017.md))。
2. リバースエンジニアしたアプリに対して、外部ストレージ API の呼び出しと Android マニフェストのストレージパーミッションをターゲットとした静的解析 ([Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md)) ツールを実行します。

静的解析ツールは、`getExternalStoragePublicDirectory`, `getExternalStorageDirectory`, `getExternalFilesDir`, `MediaStore`, `WRITE_EXTERNAL_STORAGE`, `MANAGE_EXTERNAL_STORAGE` など、共有ストレージへの書き込みに使用される可能性のあるすべての API とパーミッションを特定できる必要があります。これらの API とパーミッションの詳細については [Android ドキュメント](https://developer.android.com/training/data-storage/shared) を参照してください。

## 結果

出力には共有ストレージへの書き込みに使用される API とストレージ関連パーミッションのリストと、それらのコードの場所を含む可能性があります。

## 評価

以下の場合、テストケースは不合格です。

- アプリに Android マニフェストで宣言された適切なパーミッションがあります (例: `WRITE_EXTERNAL_STORAGE`, `MANAGE_EXTERNAL_STORAGE` など)。
- **かつ** 共有ストレージに書き込まれるデータは機密性が高く、暗号化されていません。

後者を判断するには、リバースしたコードを注意深くレビュー ([逆コンパイルした Java コードのレビュー (Reviewing Decompiled Java Code)](../../../techniques/android/MASTG-TECH-0023.md)) したり、このテストを動的なアプローチを採る他のテストと組み合わせる必要があるかもしれません。これは共有ストレージに書き込まれるデータのより完全なビューを提供することでしょう。

## 参考情報

- [ストレージ デバイスのすべてのファイルを管理する](https://developer.android.com/training/data-storage/manage-all-files)
- [共有ストレージからメディア ファイルにアクセスする](https://developer.android.com/training/data-storage/shared/media)
