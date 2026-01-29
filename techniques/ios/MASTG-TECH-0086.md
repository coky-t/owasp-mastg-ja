---
title: メソッドトレース (Method Tracing)
platform: ios
---

Objective-C メソッドの傍受は有用な iOS セキュリティテスト技法です。たとえば、データストレージ操作やネットワークリクエストに関心があるかもしれません。以下の例では、iOS 標準の HTTP API 経由で行われた HTTP(S) リクエストをログ記録するためのシンプルなトレーサーを作成します。また、このトレーサーを Safari ウェブブラウザに注入する方法も示します。

以下の例では、脱獄済みデバイスで作業していることを想定しています。そうでない場合、まず [Frida Gadget を IPA に自動的に注入する (Injecting Frida Gadget into an IPA Automatically)](MASTG-TECH-0090.md) で説明されている手順に従い、Safari アプリを Frida Gadget とともに再パッケージする必要があります。

Frida には関数トレースツールである `frida-trace` が付属しています。`frida-trace` は `-m` フラグで Objective-C メソッドを受け付けます。ワイルドカードを渡すこともできます。たとえば、`-[NSURL *]` では `frida-trace` がすべての `NSURL` クラスセレクタに自動的にフックをインストールします。これを使用して、ユーザーが URL を開いたときに Safari がどのライブラリ関数を呼び出すかを大まかに把握します。

iOS で frida-trace を使用する詳細なチュートリアルについては、[Frida ハンドブックの frida-trace セクション](https://learnfrida.info/basic_usage/#frida-trace) を参照してください。

デバイス上で Safari を実行し、デバイスが USB で接続されていることを確認します。それから以下のように `frida-trace` を起動します。

```bash
$ frida-trace -U -m "-[NSURL *]" Safari
Instrumenting functions...
-[NSURL isMusicStoreURL]: Loaded handler at "/Users/berndt/Desktop/__handlers__/__NSURL_isMusicStoreURL_.js"
-[NSURL isAppStoreURL]: Loaded handler at "/Users/berndt/Desktop/__handlers__/__NSURL_isAppStoreURL_.js"
(...)
Started tracing 248 functions. Press Ctrl+C to stop.
```

次に、Safari で新しいウェブサイトにナビゲートします。`frida-trace` コンソールにトレースされた関数呼び出しが表示されます。新しい URL リクエストオブジェクトを初期化するために `initWithURL:` メソッドが呼び出されることに注意してください。

```bash
           /* TID 0xc07 */
  20313 ms  -[NSURLRequest _initWithCFURLRequest:0x1043bca30 ]
 20313 ms  -[NSURLRequest URL]
(...)
 21324 ms  -[NSURLRequest initWithURL:0x106388b00 ]
 21324 ms     | -[NSURLRequest initWithURL:0x106388b00 cachePolicy:0x0 timeoutInterval:0x106388b80
```
