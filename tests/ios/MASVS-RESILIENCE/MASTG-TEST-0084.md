---
masvs_v1_id:
- MSTG-CODE-4
masvs_v2_id:
- MASVS-RESILIENCE-3
platform: ios
title: デバッグコードと詳細エラーログのテスト (Testing for Debugging Code and Verbose Error Logging)
masvs_v1_levels:
- R
profiles: [R]
---

## 概要

## 静的解析

ログ出力文について以下の静的解析アプローチをとることができます。

1. Xcode にアプリケーションのコードをインポートします。
2. 次の出力関数についてコードを検索します: `NSLog`, `println`, `print`, `dump`, `debugPrint`.
3. いずれか一つを見つけたら、ログ出力されるステートメントのより良いマークアップのために開発者がログ出力関数を囲うラップ関数を使用しているかどうかを判断します。そうであれば、その関数を検索に追加します。
4. 手順 2 と 3 のすべてのものについて、マクロやデバッグ状態に関連するガードがリリースビルドでログ出力なしにするように設定されているかどうかを判断します。Objective-C がプリプロセッサマクロを使用する方法の変更点に注意します。

```objectivec
#ifdef DEBUG
    // Debug-only code
#endif
```

Swift ではこの動作を有効にする手続きが変更されています。スキームで環境変数を設定するか、ターゲットのビルド設定でカスタムフラグとして設定する必要があります。Xcode 8 および Swift3 ではサポートされていないため、(アプリが Swift 2.1 のリリース構成でビルドされているかどうかを判断できる) 次の関数は推奨されていないことに注意します。

- `_isDebugAssertConfiguration`
- `_isReleaseAssertConfiguration`
- `_isFastAssertConfiguration`.

アプリケーションの設定に応じて、より多くのログ出力関数が存在する可能性があります。例えば、[CocoaLumberjack](https://github.com/CocoaLumberjack/CocoaLumberjack "CocoaLumberjack") を使用する場合、静的解析は多少異なります。

(ビルトインの) 「デバッグ管理」コードについて、ストーリーボードを調査して、アプリケーションがサポートすべき機能とは異なる機能を提供するフローやビューコントローラがあるかどうかを確認します。この機能には、デバッグビューからエラーメッセージ出力まで、カスタムスタブレスポンス構成からアプリケーション上のファイルシステムやリモートサーバーへのログ出力まで、いろいろあります。

一人の開発者として、アプリケーションのデバッグバージョンにデバッグステートメントを組み込むことは、デバッグステートメントがアプリケーションのリリースバージョンに存在しないことを確認していれば問題ありません。

Objective-C では、開発者はプリプロセッサマクロを使用してデバッグコードを除外できます。

```objectivec
#ifdef DEBUG
    // Debug-only code
#endif
```

Swift 2 では (Xcode 7 を使用して) 、すべてのターゲットにカスタムコンパイラフラグを設定する必要があります。コンパイラフラグは "-D" で始まる必要があります。したがって、デバッグフラグ `MSTG-DEBUG` を設定されている場合、以下のアノテーションが使用できます。

```objectivec
#if MSTG_DEBUG
    // Debug-only code
#endif
```

Swift 3 では (Xcode 8 を使用して) 、Build settings/Swift compiler - Custom flags の Active Compilation Conditions を設定できます。プリプロセッサを使用する代わりに、Swift3 は定義済みの条件に基づく [条件付きコンパイルブロック](https://developer.apple.com/library/content/documentation/Swift/Conceptual/BuildingCocoaApps/InteractingWithCAPIs.html#//apple_ref/doc/uid/TP40014216-CH8-ID34 "Swift conditional compilation blocks") を使用します。

```objectivec
#if DEBUG_LOGGING
    // Debug-only code
#endif
```

## 動的解析

動的解析はシミュレータとデバイスの両方で実行すべきです。開発者はデバッグコードを実行するために (リリース/デバッグモードベースの関数の代わりに) ターゲットベースの関数を使用することが時折あるためです。

1. シミュレータ上でアプリケーションを実行して、アプリの実行中にコンソールで出力を確認します。
2. デバイスを Mac に接続して、Xcode 経由でデバイス上のアプリケーションを実行し、アプリの実行中にコンソールで出力を確認します。

他の「マネージャベース」のデバッグコードでは、シミュレータとデバイスの両方でアプリケーションをクリックして、アプリのプロファイルをプリセットできる機能、実サーバーを選択する機能、API からのレスポンスを選択する機能があるかどうかを確認します。
