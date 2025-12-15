---
title: ログ記録コードを削除する (Remove Logging Code)
alias: remove-logging-code
id: MASTG-BEST-0002
platform: android
knowledge: [MASTG-KNOW-0049]
---

理想的には、リリースビルドではログ記録機能を使用せず、機密データの露出を評価しやすくすべきです。

## ProGuard の使用

製品リリースを準備する際に、[ProGuard](../tools/android/MASTG-TOOL-0022.md) (Android Studio に含まれています) などのツールを使用できます。`android.util.Log` クラスのすべてのログ記録機能が削除されているかどうかを確認するには、ProGuard 設定ファイル (proguard-rules.pro) で以下のオプションを確認します (この [ログ記録コードを削除する例](https://www.guardsquare.com/en/products/proguard/manual/examples#logging "ProGuard\'s example of removing logging code") と [Android Studio プロジェクトで ProGuard を有効にする](https://developer.android.com/studio/build/shrink-code#enable "Android Developer - Enable shrinking, obfuscation, and optimization") に関するこの記事に従います)。

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

上記の例では Log クラスのメソッドへの呼び出しが削除されることのみを確保することに注意してください。ログ記録される文字列が動的に構築される場合、文字列を構築するコードはバイトコード内に残る可能性があります。たとえば、以下のコードは暗黙的な `StringBuilder` を発行してログステートメントを構築します。

Java の例:

```java
Log.v("Private key tag", "Private key [byte format]: " + key);
```

Kotlin の例:

```kotlin
Log.v("Private key tag", "Private key [byte format]: $key")
```

しかし、コンパイルされたバイトコードは、文字列を暗黙的に構築する以下のログステートメントのバイトコードと等価です。

Java の例:

```java
Log.v("Private key tag", new StringBuilder("Private key [byte format]: ").append(key.toString()).toString());
```

Kotlin の例:

```kotlin
Log.v("Private key tag", StringBuilder("Private key [byte format]: ").append(key).toString())
```

ProGuard は `Log.v` メソッド呼び出しの削除を保証します。残りのコード (`new StringBuilder ...`) が削除されるかどうかは、コードの複雑さと [ProGuard バージョン](https://stackoverflow.com/questions/6009078/removing-unused-strings-during-proguard-optimisation "Removing unused strings during ProGuard optimization ") によって異なります。

これは、(未使用の) 文字列がプレーンテキストデータをメモリに漏洩し、デバッガやメモリダンプを介してアクセスできるため、セキュリティリスクとなります。

残念ながら、この問題に対する特効薬は存在しませんが、一つの選択肢として、単純な引数を取り、ログステートメントを内部的に構築するカスタムログ記録機能を実装することがあります。

```java
SecureLog.v("Private key [byte format]: ", key);
```

それから、その呼び出しを削除するように ProGuard を設定します。

## カスタムログ記録

カスタムログ記録機能を実装して、リリースビルドに対してのみ一度に無効にできます。
