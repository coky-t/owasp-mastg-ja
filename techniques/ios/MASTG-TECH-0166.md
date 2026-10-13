---
title: iOS アプリ内のカスタム URL スキーム登録の識別 (Identifying Custom URL Scheme Registrations in iOS Apps)
platform: ios
---

iOS アプリは `Info.plist` ファイル内でカスタム URL スキームを宣言し、デリゲートメソッドを通じて受信した URL を処理します。この技法では、登録済み URL スキームを特定し、アプリバイナリ内でそのハンドラの実装箇所を特定する方法をカバーします。

## 登録済み URL スキームについて Info.plist をチェックする

アプリバンドルの `Info.plist` ファイルは、アプリが登録しているすべてのカスタム URL スキームを `CFBundleURLTypes` の下にリストしています。[アプリの取得と抽出 (Obtaining and Extracting Apps)](MASTG-TECH-0054.md) や [アプリパッケージの探索 (Exploring the App Package)](MASTG-TECH-0058.md) を使用して IPA を抽出した後、`grep` で直接 plist を検査します。

```bash
grep -A 5 CFBundleURLSchemes ./Payload/MASTestApp.app/Info.plist
```

### クエリされた URL スキームをチェックする

`Info.plist` 内の `LSApplicationQueriesSchemes` キーでは、アプリが [`canOpenURL:`](https://developer.apple.com/documentation/uikit/uiapplication/1622952-canopenurl) を介してクエリすることを許可された URL スキームをリストしています。`CFBundleURLSchemes` と併せてそれを検査します。

```bash
grep -A 5 LSApplicationQueriesSchemes Info.plist
```

## バイナリ内の URL ハンドラメソッドの場所を特定する

登録済みスキームを特定した後、受信した URL リクエストの処理を担うデリゲートメソッドの場所を特定します。iOS アプリバイナリでは以下のセレクタが一般的に見受けられます。

### 最新のハンドラ (iOS 9 以降)

[`application:openURL:options:`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/1623112-application) は、受信した URL を処理するための現在のデリゲートメソッドです。それはソースアプリケーション識別子 (`UIApplicationOpenURLOptionsSourceApplicationKey`) を含む `options` 辞書を受取します。

### [rabin2](../../tools/generic/MASTG-TOOL-0129.md) を使用する

`rabin2` はバイナリ内のすべての Objective-C セレクタ文字列をリストします。

```bash
rabin2 -zzq MASTestApp | grep -i openurl
```

### [radare2 (iOS)](../../tools/ios/MASTG-TOOL-0073.md) を使用する

フラグ (`f`) と `~` フィルタを使用して、名前でメソッド参照を探します。

```bash
r2 -qc "aaa; f~openURL:options" MASTestApp
```

それから、`axt` を使用して、フラグ付けされたアドレスへのクロスリファレンスを探します。

```bash
r2 -qc "aaa; axt @ reloc.fixup.application:openURL:options:" MASTestApp
```

バイナリ内のどこで `UIApplicationOpenURLOptionsSourceApplicationKey` が参照されているかどうかを特定して、ハンドラが options 辞書からソースアプリケーションを読み取っていることを示します。

```bash
r2 -qc "aaa; f~UIApplicationOpenURLOptionsSourceApplicationKey" MASTestApp
```

ハンドラ関数を逆アセンブルするには、`axt` で返されたアドレスに対して `pdf` を使用します。

```bash
r2 -qc "aaa; pdf @ <handler_address>" MASTestApp
```
