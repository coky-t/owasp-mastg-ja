---
title: プロダクションビルドで詳細ログ記録とデバッグログ記録を無効にする (Disable Verbose and Debug Logging in Production Builds)
alias: remove-logging-in-production
id: MASTG-BEST-0022
platform: ios
---

`print` や [`NSLog`](https://developer.apple.com/documentation/foundation/nslog) などの安全でないログ記録メカニズムを使用することは避ける必要があります。これらの API は機密性の高いランタイムデータをシステムログにさらす可能性があり、デバイスにアクセスできる攻撃者が取得する可能性があります。代わりに、iOS 10.0 以降で利用可能な [Apple の統合ログ記録システム](https://developer.apple.com/documentation/os/logging) (Swift では `Logger`、Objective-C では `os_log`) を採用する必要があります。

`print` や `NSLog` に依存している場合:

- ログがシステム診断に至り、攻撃者がアクセスできるままとなる可能性があります。
- デバッガや脱獄済みデバイスは詳細なログメッセージをキャプチャできます。
- トークン、パスワード、PII を露出するリスクがあります。

## 統合ログ記録機能を使用する

統合ログ記録に切り替えると、構造化されプライバシーに配慮したログ記録となり、プロダクション環境でもより安全になります。[`Logger`](https://developer.apple.com/documentation/os/logger) (Swift) や [`os_log`](https://developer.apple.com/documentation/os/os_log) (Objective-C) を採用する際に使用できる主な機能は以下のとおりです。

### プライバシー修飾子

情報をログ記録する際には、個人識別子、認証トークン、シークレットなどの機密データを保護することが不可欠です。Apple の統合ログ記録システムは [プライバシー修飾子](https://developer.apple.com/documentation/os/oslogprivacy) を提供しており、ログにデータが出現する方法を制御できます。

- **`.public`**: すべてのログに表示しても安全であると明示的にマークします。**機密性のないデバッグ情報** にのみ使用します。
- **`.private`**: 永続ログの値は訂正しますが、デバッグ時は依然としてメモリに表示します (PII、シークレット、トークン、機密データなど)。
- **`.private(mask:)`**: データの相関関係を維持できます。たとえば、ハッシュマスクを適用すると、生データを露出することなく、ログ全体で重複する値を識別できます。
- **`.sensitive`**: `.private` と同様に動作しますが、プライベートデータのログ記録がグローバルに有効にされた場合でも、訂正されたままとなります。

### ログレベル

統合ログ記録は [ログレベル](https://developer.apple.com/documentation/os/oslogtype) をサポートしており、重要度と重大度に基づいてメッセージを分類および優先順位付けするのに役立ちます。適切なログレベルを割り当てることで、プロダクションで表示するメッセージを制御したり、デバッグを支援したり、注意を要する重大な問題を迅速に特定できます。

- **`debug`**: 詳細なデバッグ情報に使用されます。
- **`info`**: 一般的な操作メッセージに使用されます。
- **`error`**: 何かが失敗したが、アプリは継続可能な場合に使用されます。
- **`fault`**: 緊急対応を要する深刻な問題 (クラッシュ、破損など) に使用されます。

## プロダクションではマクロを使用してログ記録を無効にする

最大のセキュリティを確保するには、これらのログ記録呼び出しをアプリから完全に削除するのが最も安全なアプローチです。以下は、コンパイル時にアプリケーションからログ記録 API を排除する方法を示したサンプルコードです。

### 1. Swift

```swift
#if DEBUG
print("Hello world")
#endif
```

### 2. Objective-C

```objectivec
#ifdef DEBUG 
# define NSLog (...) NSLog(__VA_ARGS__) 
#else 
# define NSLog (...) 
#endif
```

次に、開発ビルド用に `Apple Clang - Preprocessing > Preprocessor Macros` で `DEBUG` フラグを設定する必要があります。
