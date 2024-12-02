---
platform: android
title: ログ記録 API の実行時使用 (Runtime Use of Logging APIs)
id: MASTG-TEST-0203
apis: [Log, Logger, System.out.print, System.err.print, java.lang.Throwable#printStackTrace]
type: [dynamic]
weakness: MASWE-0001
mitigations: [MASTG-MITIG-0002]
---

## 概要

Android プラットフォームでは、`Log`, `Logger`, `System.out.print`, `System.err.print`, `java.lang.Throwable#printStackTrace` などのログ記録 API によって意図せず機密情報の漏洩につながる可能性があります。ログメッセージは共有メモリバッファである logcat に記録され、Android 4.1 (API レベル 16) 以降では `READ_LOGS` パーミッションを宣言する特権システムアプリケーションのみがアクセスできます。とはいえ、Android システムの広大なエコシステムには `READ_LOGS` 権限を持つプリロードされたアプリが含まれており、機密データ開示のリスクが高まっています。したがって、logcat への直接的なログ記録はデータ漏洩の危険性があるため一般的に推奨されません。

## 手順

1. アプリをインストールして実行します。
2. ログ出力を解析したいモバイルアプリの画面に移動します。
3. 実行中のアプリにアタッチし、ログ記録 API をターゲットにしてメソッドトレース ([メソッドトレース (Method Tracing)](../../../techniques/android/MASTG-TECH-0033.md)) ([Frida for Android](../../../tools/android/MASTG-TOOL-0001.md) などを使用) を実行し、出力を保存します。

## 結果

出力には現在実行しているアプリでログ記録 API が使用されている場所のリストを含む可能性があります。

## 評価

これらの API を使用してログ記録されている機密データを見つけることができた場合、そのテストケースは不合格です。
