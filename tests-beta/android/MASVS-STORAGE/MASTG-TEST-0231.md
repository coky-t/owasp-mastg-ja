---
platform: android
title: ログ記録 API への参照 (References to Logging APIs)
id: MASTG-TEST-0231
apis: [Log, Logger, System.out.print, System.err.print, java.lang.Throwable#printStackTrace, android.util.Log]
type: [static]
weakness: MASWE-0001
---

## 概要

このテストでは、アプリが `android.util.Log`, `Log`, `Logger`, `System.out.print`, `System.err.print`, `java.lang.Throwable#printStackTrace` などのログ記録 API を使用しているかどうかを検証します。

## 手順

1. [Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md) を [semgrep](../../../tools/generic/MASTG-TOOL-0110.md) などのツールとともに使用して、すべてのログ記録 API を特定します。

## 結果

出力にはログ記録 API が使用されている場所のリストを含む可能性があります。

## 評価

アプリが、リストされている場所のいずれかから機密情報をログ記録している場合、そのテストは不合格です。理想的には、リリースビルドではログ記録関数を使用せず、機密データの露出を評価しやすくすることです。

## 緩和

製品リリースを準備している間、[ProGuard](../../../tools/android/MASTG-TOOL-0022.md) (Android Studio に含まれています) などのツールを使用できます。`android.util.Log` クラスからのすべてのログ記録関数が削除されているかどうかを判断するには、ProGuard 設定ファイル (proguard-rules.pro) に以下のオプションをチェックします (この [ログ記録コードを削除する例](https://www.guardsquare.com/en/products/proguard/manual/examples#logging "ProGuard\'s example of removing logging code") や、この記事 [Android Studio プロジェクトで ProGuard を有効にする](https://developer.android.com/studio/build/shrink-code#enable "Android Developer - Enable shrinking, obfuscation, and optimization") に従います)。

```default
-assumenosideeffects class android.util.Log
{
  public static boolean isLoggable(java.lang.String, int);
  public static int v(...);
  public static int i(...);
  public static int w(...);
  public static int d(...);
  public static int e(...);
  public static int wtf(...);
}
```

上記の例では、Log クラスのメソッドへの呼び出しが削除されることを確保しているだけであることに注意してください。ログに記録される文字列が動的に構築される場合、文字列を構築するコードはバイトコード内に残る可能性があります。

あるいは、カスタムログ記録機能を実装し、リリースビルドに限ってそれを無効にすることもできます。
