---
title: Cycript
platform: ios
source: https://www.cycript.org/
status: deprecated
deprecation_note: Cycript はもはや積極的にメンテナンスされておらず、最新の iOS バージョンでは動作しません。最後に意味のあるアップデートが行われたのは 2009 年から 2013 年の間です。cynject などの主要コンポーネントは Cydia Substrate の変更により 2019 年ごろの iOS 12 で動作しなくなり、修正されていません。Frida は、より広範な互換性、積極的なサポート、より強力な動的計装機能を提供します。
covered_by: [MASTG-TOOL-0039]
---

Cycript は Jay Freeman (別名 Saurik) が開発したスクリプト言語です。これは実行中のプロセスに JavaScriptCore 仮想マシンを注入します。Cycript の対話型コンソールを使用して、ユーザーは Objective-C++ と JavaScript のハイブリッド構文でプロセスを操作できます。実行中のプロセス内の Objective-C クラスにアクセスすることやインスタンス化することがサポートされています。iOS 上で Cydia Substrate Extensions として知られる [Cydia](MASTG-TOOL-0047.md) ランタイムパッチを開発するための標準フレームワークである [Cydia Substrate](https://www.cydiasubstrate.com/) を使用して、デバッガと同様に Cycript を実行中のプロセスに注入できます。Cycript には、コード注入をサポートするツールである Cynject を含みます。

Cycript をインストールするには、まず SDK をダウンロードし、展開して、インストールします。

```bash
#on iphone
$ wget https://cydia.saurik.com/api/latest/3 -O cycript.zip && unzip cycript.zip
$ sudo cp -a Cycript.lib/*.dylib /usr/lib
$ sudo cp -a Cycript.lib/cycript-apl /usr/bin/cycript
```

対話型 Cycript シェルを起動するには、"./cycript"、または Cycript がパス上にある場合は "cycript" を実行します。

```bash
$ cycript
cy#
```

実行中のプロセスに注入するには、まずプロセス ID (PID) を見つける必要があります。アプリケーションを実行し、アプリケーションがフォアグラウンドにあることを確認します。`cycript -p <PID>` を実行すると、プロセスに Cycript を注入します。例として、SpringBoard (常に実行されています) に注入してみます。

```bash
$ ps -ef | grep SpringBoard
501 78 1 0 0:00.00 ?? 0:10.57 /System/Library/CoreServices/SpringBoard.app/SpringBoard
$ ./cycript -p 78
cy#
```

最初に試してみることの一つは、アプリケーションインスタンス (`UIApplication`) を取得することです。これは Objective-C 構文を使用できます。

```bash
cy# [UIApplication sharedApplication]
cy# var a = [UIApplication sharedApplication]
```

ここでこの変数を使用して、アプリケーションのデリゲートクラスを取得します。

```bash
cy# a.delegate
```

Cycript で SpringBoard のアラートメッセージをトリガーしてみましょう。

```bash
cy# alertView = [[UIAlertView alloc] initWithTitle:@"OWASP MASTG" message:@"Mobile Application Security Testing Guide"  delegate:nil cancelButtonitle:@"OK" otherButtonTitles:nil]
#"<UIAlertView: 0x1645c550; frame = (0 0; 0 0); layer = <CALayer: 0x164df160>>"
cy# [alertView show]
cy# [alertView release]
```

<img src="../../Document/Images/Chapters/0x06c/cycript_sample.png" width="300px" />

Cycript でアプリのドキュメントディレクトリを見つけます。

```bash
cy# [[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask][0]
#"file:///var/mobile/Containers/Data/Application/A8AE15EE-DC8B-4F1C-91A5-1FED35212DF/Documents/"
```

コマンド `[[UIApp keyWindow] recursiveDescription].toString()` は `keyWindow` のビュー階層を返します。`keyWindow` のすべてのサブビューとサブサブビューの説明が表示されます。インデントスペースはビュー間の関係を反映しています。たとえば、`UILabel`、`UITextField`、`UIButton` は `UIView` のサブビューです。

```xml
cy# [[UIApp keyWindow] recursiveDescription].toString()
`<UIWindow: 0x16e82190; frame = (0 0; 320 568); gestureRecognizers = <NSArray: 0x16e80ac0>; layer = <UIWindowLayer: 0x16e63ce0>>
  | <UIView: 0x16e935f0; frame = (0 0; 320 568); autoresize = W+H; layer = <CALayer: 0x16e93680>>
  |    | <UILabel: 0x16e8f840; frame = (0 40; 82 20.5); text = 'i am groot!'; hidden = YES; opaque = NO; autoresize = RM+BM; userInteractionEnabled = NO; layer = <_UILabelLayer: 0x16e8f920>>
  |    | <UILabel: 0x16e8e030; frame = (0 110.5; 320 20.5); text = 'A Secret Is Found In The ...'; opaque = NO; autoresize = RM+BM; userInteractionEnabled = NO; layer = <_UILabelLayer: 0x16e8e290>>
  |    | <UITextField: 0x16e8fbd0; frame = (8 141; 304 30); text = ''; clipsToBounds = YES; opaque = NO; autoresize = RM+BM; gestureRecognizers = <NSArray: 0x16e94550>; layer = <CALayer: 0x16e8fea0>>
  |    |    | <_UITextFieldRoundedRectBackgroundViewNeue: 0x16e92770; frame = (0 0; 304 30); opaque = NO; autoresize = W+H; userInteractionEnabled = NO; layer = <CALayer: 0x16e92990>>
  |    | <UIButton: 0x16d901e0; frame = (8 191; 304 30); opaque = NO; autoresize = RM+BM; layer = <CALayer: 0x16d90490>>
  |    |    | <UIButtonLabel: 0x16e72b70; frame = (133 6; 38 18); text = 'Verify'; opaque = NO; userInteractionEnabled = NO; layer = <_UILabelLayer: 0x16e974b0>>
  |    | <_UILayoutGuide: 0x16d92a00; frame = (0 0; 0 20); hidden = YES; layer = <CALayer: 0x16e936b0>>
  |    | <_UILayoutGuide: 0x16d92c10; frame = (0 568; 0 0); hidden = YES; layer = <CALayer: 0x16d92cb0>>`
```

また、指定された Objective-C クラスのインスタンスをヒープから検索する `choose` などの Cycript の組み込み関数を使用することもできます。

```bash
cy# choose(SBIconModel)
[#"<SBIconModel: 0x1590c8430>"]
```

詳しくは [Cycript マニュアル](http://www.cycript.org/manual/ "Cycript Manual") をご覧ください。
