---
title: 内部 IPC には明示的なインテントを使用する (Use Explicit Intents for Internal IPC)
alias: use-explicit-intents-for-internal-ipc
id: MASTG-BEST-0056
platform: android
knowledge: [MASTG-KNOW-0025]
---

同じアプリ内のコンポーネント間で通信する場合には [明示的インテント](https://developer.android.com/guide/components/intents-filters#ExplicitIntent) を使用します。明示的インテントはパッケージ名またはクラス名によってターゲットコンポーネントを直接指定します。そのインテントは意図した受信者にのみ配信され、通常のインテント解決を通じてサードパーティアプリによって傍受できないようにします。

## Java/Kotlin

インテントを送信する前に [`Intent.setPackage`](https://developer.android.com/reference/android/content/Intent#setPackage(java.lang.String)) でターゲットパッケージを設定するか、特定のコンポーネントをターゲットとします。

```kotlin
// Explicit by package - restricts delivery to your own app
val intent = Intent("com.example.app.PROCESS_DATA").apply {
    setPackage("com.example.app")
    putExtra("key", "value")
}
startActivity(intent)

// Explicit by component - the most restrictive form
val intent = Intent(context, TargetActivity::class.java).apply {
    putExtra("key", "value")
}
startActivity(intent)
```

暗黙的インテントに機密データ (トークン、クレデンシャル、API キー) を送信してはいけません。Android は、互換性のある [`<intent-filter>`](https://developer.android.com/guide/topics/manifest/intent-filter-element) 要素を宣言するインストール済みアプリを照合することで、暗黙的インテントを解決します。そのため、任意の一致するアプリが受信者として選択され、インテントの extras を受け取ることができます。

## マニフェストの設定

内部コンポーネントについては、意図せず他のアプリケーションに公開されないようにします。`AndroidManifest.xml` を適切に保護するための詳細な手順については、[Android アプリコンポーネントへのアクセスを制限する (Restrict Access to Android App Components)](MASTG-BEST-0052.md) を参照してください。
