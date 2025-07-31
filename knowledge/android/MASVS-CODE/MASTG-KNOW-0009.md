---
masvs_category: MASVS-CODE
platform: android
title: StrictMode
---

StrictMode はアプリのメインスレッドへの偶発的なディスクやネットワークアクセスなどの違反を検出するための開発者ツールです。効率の良いコード実装など優れたコーディングプラクティスをチェックするためにも使用できます。

[ThreadPolicy Builder](https://developer.android.com/reference/android/os/StrictMode.ThreadPolicy.Builder) と [VmPolicy Builder](https://developer.android.com/reference/android/os/StrictMode.VmPolicy.Builder) を使用して、さまざまなポリシーを設定できます。

検出したポリシー違反に対する反応は、一つ以上の `penalty*` メソッドを使用して設定できます。たとえば、`penaltyLog()` を有効にすると、ポリシー違反をシステムログにログ記録できます。

以下はメインスレッドへのディスクおよびネットワークアクセスに対してポリシーを有効にした [`StrictMode`](https://developer.android.com/reference/android/os/StrictMode.html "StrictMode Class") の例です。これが検出されると、ログメッセージがシステムログに書き込まれ、アプリは強制的にクラッシュします。

```java
public void onCreate() {
     if (BuildConfig.DEBUG) {
         StrictMode.setThreadPolicy(new StrictMode.ThreadPolicy.Builder()
                 .detectDiskReads()
                 .detectDiskWrites()
                 .detectNetwork()   // or .detectAll() for all detectable problems
                 .penaltyLog()
                 .build());
         StrictMode.setVmPolicy(new StrictMode.VmPolicy.Builder()
                 .detectLeakedSqlLiteObjects()
                 .detectLeakedClosableObjects()
                 .penaltyLog()
                 .penaltyDeath()
                 .build());
     }
     super.onCreate();
 }
```

アプリのデバッグビルドでのみ StrictMode ポリシーを自動的に有効にするには、`BuildConfig.DEBUG` 条件での `if` ステートメントにポリシーを含めることをお勧めします。
