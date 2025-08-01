---
masvs_category: MASVS-RESILIENCE
platform: android
title: リバースエンジニアリングツールの検出 (Detection of Reverse Engineering Tools)
---

リバースエンジニアが一般的に使用するツール、フレームワーク、アプリが存在する場合、アプリをリバースエンジニアリングしようとしていることを示している可能性があります。これらのツールの中にはルート化されたデバイスでのみ実行できるものもあれば、アプリをデバッグモードで動作するものや、モバイルフォンでのバックグラウンドサービス開始に依存するものもあります。したがって、リバースエンジニアリング攻撃を検知してそれに対応するためにアプリが実装する方法はさまざまです。たとえば、アプリ自体を終了します。

関連するアプリケーションパッケージ、ファイル、プロセス、またはその他のツール固有の変更とアーティファクトを探すことで、変更のない状態でインストールされた一般的なリバースエンジニアリングツールを検出できます。以下の例では、このガイドで広く使用されている Frida インストルメンテーションフレームワークを検出するさまざまな方法について説明します。ElleKit や Xposed などの他のツールも同様に検出できます。DBI/インジェクション/フックツールは後述するランタイム完全性チェックを通じて暗黙的に検出できることが多いことに注意してください。

たとえば、ルート化されたデバイスのデフォルト設定では Frida はデバイス上で frida-server として実行します。ターゲットアプリに (frida-trace や Frida REPL などを介して) 明示的にアタッチすると、Frida はアプリのメモリに frida-agent を注入します。したがって、アプリにアタッチした後 (前ではなく) そこにあることが期待できます。 `/proc/<pid>/maps` をチェックすると、frida-agent が frida-agent-64.so として見つかります。

```bash
bullhead:/ # cat /proc/18370/maps | grep -i frida
71b6bd6000-71b7d62000 r-xp  /data/local/tmp/re.frida.server/frida-agent-64.so
71b7d7f000-71b7e06000 r--p  /data/local/tmp/re.frida.server/frida-agent-64.so
71b7e06000-71b7e28000 rw-p  /data/local/tmp/re.frida.server/frida-agent-64.so
```

もう一つの方法 (非ルート化デバイスでも機能します) は APK に [frida-gadget](https://www.frida.re/docs/gadget/ "Frida Gadget") を埋め込み、アプリがそれをネイティブライブラリの一つとしてロードすることを強制するものです。アプリの起動後に (明示的にアタッチする必要はありません) アプリのメモリマップを調べると、埋め込まれた frida-gadget が libfrida-gadget.so として見つかります。

```bash
bullhead:/ # cat /proc/18370/maps | grep -i frida

71b865a000-71b97f1000 r-xp  /data/app/sg.vp.owasp_mobile.omtg_android-.../lib/arm64/libfrida-gadget.so
71b9802000-71b988a000 r--p  /data/app/sg.vp.owasp_mobile.omtg_android-.../lib/arm64/libfrida-gadget.so
71b988a000-71b98ac000 rw-p  /data/app/sg.vp.owasp_mobile.omtg_android-.../lib/arm64/libfrida-gadget.so
```

Frida が残したこれら二つの痕跡を見れば、それらを検出するのは簡単な作業であることがすぐに想像できるかもしれません。そして実際、その検出をバイパスすることは非常に簡単です。しかし物事はもっと複雑になる可能性があります。以下の表はいくつかの典型的な Frida 検出方法とその有効性についての簡単な説明を簡潔に示しています。

> 以下の検出方法の一部は [Berdhard Mueller の記事 "The Jiu-Jitsu of Detecting Frida"](https://web.archive.org/web/20181227120751/http://www.vantagepoint.sg/blog/90-the-jiu-jitsu-of-detecting-frida "The Jiu-Jitsu of Detecting Frida") (archived) で紹介されています。詳細とコードスニペット例についてはそちらを参照してください。

| 手法 | 説明 | 考察 |
| --- | --- | --- |
| **アプリ署名をチェックする** | APK 内に frida-gadget を埋め込むには、再パッケージ化して再署名する必要があります。アプリの起動時に APK の署名をチェック (例: API レベル 28 以降では [GET_SIGNING_CERTIFICATES](https://developer.android.com/reference/android/content/pm/PackageManager#GET_SIGNING_CERTIFICATES "GET_SIGNING_CERTIFICATES")) し、API にピン留めしたものと比較します。 | これは残念ながら、APK にパッチを当てたり、システムコールフックを行うなどで、バイパスするのは非常に簡単です。 |
| **環境に関連するアーティファクトをチェックする** | アーティファクトにはパッケージファイル、バイナリ、ライブラリ、プロセス、一時ファイルなどがあります。Frida の場合、これはターゲット (ルート化された) システムで実行されている frida-server (TCP 経由で Frida を公開する役割を担うデーモン) である可能性があります。実行中のサービス ([`getRunningServices`](https://developer.android.com/reference/android/app/ActivityManager.html#getRunningServices%28int%29 "getRunningServices")) とプロセス (`ps`) を調べて、名前が "frida-server" であるものを探します。また、ロードされたライブラリのリストを調べて、疑わしいもの (名前に "frida" が含まれているものなど) をチェックします。 | Android 7.0 (API レベル 24) 以降、実行中のサービスやプロセスを調べても、アプリ自体によって起動されていないため、frida-server のようなデーモンは表示されません。たとえ可能であったとしても、これをバイパスするには関連する Frida アーティファクト (frida-server/frida-gadget/frida-agent) の名前を変えるだけで簡単でしょう。 |
| **オープン TCP ポートをチェックする** | frida-server プロセスはデフォルトで TCP ポート 27042 にバインドしています。このポートがオープンであるかどうかをチェックすることもデーモンを検出する方法の一つです。 | この方法はデフォルトモードの frida-server を検出しますが、リスニングポートはコマンドライン引数で変更できるため、これをバイパスすることは少し簡単すぎます。 |
| **D-Bus 認証に応答するポートをチェックする** | `frida-server` は通信に D-Bus プロトコルを使用するため、D-Bus 認証に応答することが期待できます。すべてのオープンポートに D-Bus 認証メッセージを送信し、応答をチェックし、`frida-server` が現れることを期待します。 | これは `frida-server` を検出するかなり堅実な方法ですが、Frida は frida-server を必要としない別の動作モードを提供しています。 |
| **既知のアーティファクトについてプロセスメモリをスキャンする** | メモリをスキャンして、Frida のライブラリで見つかるアーティファクト (すべてのバージョンの frida-gadget と frida-agent に現れる文字列 "LIBFRIDA" など) を探します。たとえば、 `Runtime.getRuntime().exec` を使用して、 `/proc/self/maps` や `/proc/<pid>/maps` (Android バージョンによる) にリストされているメモリマッピングを繰り返して文字列を探します。 | この方法はもう少し効果的で、特に難読化を加えている場合や複数のアーティファクトをスキャンしている場合には、Frida だけでバイパスするのは困難です。しかし、選択したアーティファクトは Frida バイナリにパッチが当てられている可能性があります。ソースコードは [Berdhard Mueller の GitHub](https://github.com/muellerberndt/frida-detection-demo/blob/master/AntiFrida/app/src/main/cpp/native-lib.cpp "frida-detection-demo") にあります。 |

この表は網羅からは程遠いことを忘れないでください。[名前付きパイプ](https://en.wikipedia.org/wiki/Named_pipe "Named Pipes") (frida-server が外部通信に使用) と [トランポリン](https://en.wikipedia.org/wiki/Trampoline_%28computing%29 "Trampolines") (関数のプロローグに挿入された間接的なジャンプベクトル) の検出について話しましょう。 これは ElleKit や Frida の Interceptor の検出に役立ちます。その他多くの技法が存在し、これらはそれぞれ、ルート化されたデバイスを使用しているかどうか、ルート化手法の特定のバージョンやツール自体のバージョンによって異なります。さらに、アプリはさまざまな難読化技法を使用して実装された保護メカニズムの検出をより困難にすることができます。結局のところ、これは信頼できない環境 (ユーザーデバイスで実行されているアプリ) で処理されるデータを保護するいたちごっこの一環です。

> これらのコントロールはリバースエンジニアリングプロセスの複雑さを増すだけであることに注意することが重要です。使用する場合、最善のアプローチはコントロールを個別に使用するのではなく、巧みに組み合わせることです。ただし、リバースエンジニアリングは常にデバイスにフルアクセスできるので必ず勝利できるため、いずれも 100% の効果を保証することはできません。また、いくつかのコントロールをアプリに統合すると、アプリの複雑さが増し、パフォーマンスに影響を与える可能性があることも考慮する必要があります。
