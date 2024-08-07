---
masvs_v1_id:
- MSTG-STORAGE-3
masvs_v2_id:
- MASVS-STORAGE-2
platform: ios
title: 機密データのログチェック (Checking Logs for Sensitive Data)
masvs_v1_levels:
- L1
- L2
---

## 概要

## 静的解析

以下のキーワードを使用して、アプリのソースコードに定義済みログ出力ステートメントとカスタムログ出力ステートメントがないかチェックします。

-定義済み関数と組み込み関数:
    - NSLog
    - NSAssert
    - NSCAssert
    - fprintf
-カスタム関数:
    - Logging
    - Logfile

この問題に対する一般的なアプローチは、開発およびデバッグ用に define を使用して `NSLog` ステートメントを有効にし、ソフトウェアを出荷する前にそれらを無効することです。これを行うには以下のコードを適切な PREFIX_HEADER (\*.pch) ファイルに追加します。

```objectivec
#ifdef DEBUG
#   define NSLog (...) NSLog(__VA_ARGS__)
#else
#   define NSLog (...)
#endif
```

## 動的解析

[システムログの監視 (Monitoring System Logs)](../../../techniques/ios/MASTG-TECH-0060.md) を参照し、セットアップが完了したら、機密性の高いユーザー情報を入力する入力フィールドを表示する画面に移動します。

いずれかの方法を開始した後、入力フィールドを埋めます。出力に機密データが表示される場合、アプリはこのテストに不合格になります。
