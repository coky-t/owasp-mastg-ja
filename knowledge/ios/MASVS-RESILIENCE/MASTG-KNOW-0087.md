---
masvs_category: MASVS-RESILIENCE
platform: ios
title: リバースエンジニアリングツール検出 (Reverse Engineering Tools Detection)
---

リバースエンジニアが一般的に使用するツール、フレームワーク、アプリの存在はリバースエンジニアアプリの試みを示していると考えられます。これらのツールには脱獄済みデバイスでのみ実行できるものもあれば、アプリを強制的にデバッグモードにしたり、モバイルフォンのバックグラウンドサービスの開始に依存するものもあります。したがって、リバースエンジニアリング攻撃を検出し、それ自体を終了させるなどの対応を実装する方法はさまざまです。

関連するアプリケーションパッケージ、ファイル、プロセス、またはその他のツール固有の改変や成果物を探すことで、改変されていない形式でインストールされている一般的なリバースエンジニアリングツールを検出できます。以下の例では、Frida 計装フレームワークを検出するさまざまな方法について説明します。Frida 計装フレームワークはこのガイドと現実世界でも広く使用されています。ElleKit などの他のツールも同様に検出できます。インジェクション、フッキング、DBI (動的バイナリ計装) ツールは、以下で説明する実行時完全性チェックを通じて暗黙的に検出できることが多いことに注意します。

**バイパス:**

リバースエンジニアリングツールの検出をバイパスする際には以下の手順を参照にしてください。

1. アンチリバースエンジニアリング機能にパッチを当てます。radare2/[iaito](https://github.com/radareorg/iaito "iaito") や Ghidra を使用してバイナリにパッチを当て、望ましくない動作を無効にします。
2. Frida や ElleKit を使用して、Objective-C/Swift やネイティブレイヤでファイルシステム API を フックします。改変されたファイルではなく、元のファイルのハンドルを返します。

## Frida の検出

Frida は脱獄済みデバイス上ではデフォルト設定 (インジェクションモード) で frida-server という名前で動作します。ターゲットアプリに明示的に (frida-trace や Frida CLI などを介して) アタッチすると、Frida はアプリのメモリ内に frida-agent を注入します。したがって、アプリにアタッチした後 (前ではありません) では、それが見つかるはずです。Android では、 `proc` ディレクトリのプロセス ID のメモリマップ (`/proc/<pid>/maps`) で文字列 "frida" を grep するだけなので、これを検証するのは非常に簡単です。
しかし、 iOS では `proc` ディレクトリが利用できませんが、関数 `_dyld_image_count` を利用してアプリにロードされている動的ライブラリを一覧表示できます。

Frida はいわゆる組み込みモードでも動作できます。これは脱獄済みではないデバイスでも機能します。 [frida-gadget](https://www.frida.re/docs/gadget/ "Frida Gadget") を IPA に組み込み、それをネイティブライブラリの一つとしてロードすることをアプリに _強制_ します。

ARM コンパイルされたバイナリやその外部ライブラリなどのアプリケーションの静的コンテンツは `<Application>.app` ディレクトリ内に保存されます。 `/var/containers/Bundle/Application/<UUID>/<Application>.app` ディレクトリのコンテンツを調べると、組み込まれた frida-gadget が FridaGadget.dylib として見つかります。

```bash
iPhone:/var/containers/Bundle/Application/AC5DC1FD-3420-42F3-8CB5-E9D77C4B287A/SwiftSecurity.app/Frameworks root# ls -alh
total 87M
drwxr-xr-x 10 _installd _installd  320 Nov 19 06:08 ./
drwxr-xr-x 11 _installd _installd  352 Nov 19 06:08 ../
-rw-r--r--  1 _installd _installd  70M Nov 16 06:37 FridaGadget.dylib
-rw-r--r--  1 _installd _installd 3.8M Nov 16 06:37 libswiftCore.dylib
-rw-r--r--  1 _installd _installd  71K Nov 16 06:37 libswiftCoreFoundation.dylib
-rw-r--r--  1 _installd _installd 136K Nov 16 06:38 libswiftCoreGraphics.dylib
-rw-r--r--  1 _installd _installd  99K Nov 16 06:37 libswiftDarwin.dylib
-rw-r--r--  1 _installd _installd 189K Nov 16 06:37 libswiftDispatch.dylib
-rw-r--r--  1 _installd _installd 1.9M Nov 16 06:38 libswiftFoundation.dylib
-rw-r--r--  1 _installd _installd  76K Nov 16 06:37 libswiftObjectiveC.dylib
```

Frida が _残した_ これらの _トレース_ を見ると、 Frida を検出することは簡単な作業であると想像できることでしょう。そしてこれらのライブラリを検出することは簡単ですが、そのような検出をバイパスすることも同様に簡単です。ツールの検出はいたちごっこであり、事態はさらに複雑になるかもしれません。以下の表は典型的な Frida 検出方法とその有効性について簡単な説明をまとめたものです。

<div style="page-break-after: always;">
</div>

> [IOSSecuritySuite](../../../tools/ios/MASTG-TOOL-0141.md) には以下の検出方法の一部が実装されています。

| 手法 | 説明 | 考察 |
| --- | --- | --- |
| **関連する成果物がないか環境をチェックする** | 成果物にはパッケージ化されたファイル、バイナリ、ライブラリ、プロセス、一時ファイルがあります。 Frida の場合、これはターゲット (脱獄済み) システムで動作している frida-server (TCP 経由で Frida を公開するためのデーモン) 、またはアプリによりロードされた frida ライブラリです。 | 脱獄されていないデバイス上の iOS アプリでは実行中のサービスを検査することはできません。 Swift メソッド [CommandLine](https://developer.apple.com/documentation/swift/commandline "CommandLine") は iOS 上での実行中のプロセスに関する情報を照会することはできませんが、[NSTask](https://stackoverflow.com/a/56619466 "How can I run Command Line commands or tasks with Swift in iOS?") を使用するなどの非公式な方法があります。とはいえ、この手法を使用すると、App Store レビュープロセスでアプリがリジェクトされるでしょう。iOS アプリ内で実行中のプロセスの照会やシステムコマンドの実行に使用できる他の公開 API はありません。仮に可能であるとしても、これをバイパスすることは簡単であり、対応する Frida 成果物 (frida-server/frida-gadget/frida-agent) の名前を変更するだけです。Frida を検出するもう一つの方法は、ロードされたライブラリのリストをウォークスルーして、疑わしいもの (名前に "frida" を含むものなど) をチェックすることです。これは `_dyld_get_image_name` を使用して実行できます。 |
| **TCP ポートが開いているかをチェックする** | frida-server プロセスはデフォルトで TCP ポート 27042 にバインドされています。このポートが開いているかどうかをテストすることがデーモンを検出するもう一つの方法です。 | この手法はデフォルトモードでの frida-server を検出しますが、リスニングポートはコマンドライン引数で変更できるため、これをバイパスすることは非常に簡単です。 |
| **D-Bus Auth に応答するポートをチェックする** | `frida-server` は D-Bus プロトコルを使用して通信するため、D-Bus AUTH に応答することが期待できます。開いているすべてのポートに D-Bus AUTH メッセージを送信し、`frida-server` がそれ自体を明らかにすることを期待して回答をチェックします。 | これは `frida-server` を検出するかなり堅牢な方法ですが、Frida は frida-server を必要としない代替の操作モードを提供しています。 |

この表は完全ではないことを忘れないでください。例えば、他に二つの検出メカニズムが考えられます。

- [名前付きパイプ](https://en.wikipedia.org/wiki/Named_pipe "Named Pipes") の検出 (frida-server が外部通信に使用しています)
- [トランポリン](https://en.wikipedia.org/wiki/Trampoline_%28computing%29 "Trampolines") の検出 (iOS アプリでのトランポリンを検出するための詳細な説明とサンプルコードについては ["iOS アプリケーションでの SSL 証明書ピン留めのバイパスを防止する"](https://www.guardsquare.com/en/blog/iOS-SSL-certificate-pinning-bypassing "Prevent bypassing of SSL certificate pinning in iOS applications") を参照してください)

いずれも Substrate や Frida's Interceptor を検出するのに _役立ち_ ますが、たとえば、 Frida's Stalker に対しては効果的ではありません。これらの各検出方法が成功するかどうかは、脱獄済みデバイスを使用しているかどうか、特定バージョンの脱獄および手法やツール自体のバージョンにより依存することを忘れないでください。最後に、これはコントロールされていない環境 (エンドユーザーのデバイス) で処理されているデータを保護するいたちごっこの一部です。
