---
title: Frida
platform: generic
source: https://github.com/frida/frida
---

[Frida](https://www.frida.re "Frida") は Ole André Vadla Ravnås によって書かれたフリーでオープンソースの動的コード計装ツールキットで、[QuickJS](https://bellard.org/quickjs/) JavaScript エンジン (以前は [Duktape](https://duktape.org/ "Duktape JavaScript Engine") と [V8](https://v8.dev/docs "V8 JavaScript Engine")) を計装されたプロセスに注入することで機能します。Frida は Android と iOS (および [その他のプラットフォーム](https://www.frida.re/docs/home/ "So what is Frida, exactly?")) のネイティブアプリで JavaScript のスニペットを実行できます。

<img src="../../Document/Images/Chapters/0x04/frida_logo.png" style="width: 80%; border-radius: 5px; margin: 2em" />

Frida をローカルにインストールするには、以下を実行するだけです。

```bash
pip install frida-tools
```

また詳細については [インストールページ](https://www.frida.re/docs/installation/ "Frida Installation") を参照してください。

コードはいくつかの方法で注入できます。たとえば、Xposed は Android アプリローダーを永続的に変更し、新しいプロセスが開始されるたびに独自のコードを実行するためのフックを提供します。
対照的に、Frida はプロセスメモリに直接コードを書き込むことでコードインジェクションを実装します。実行中のアプリにアタッチすると、以下のようになります。

- Frida は ptrace を使用して実行中のプロセスのスレッドをハイジャックします。このスレッドはメモリのチャンクを割り当て、ミニブートストラッパーを投入するために使用されます。
- ブートストラッパーは新しいスレッドを開始し、デバイス上で動作している Frida デバッグサーバーに接続し、Frida エージェント (`frida-agent.so`) を含む共有ライブラリをロードします。
- エージェントはツール (Frida REPL やカスタム Python スクリプトなど) への双方向通信チャネルを確立します。
- ハイジャックされたスレッドは元の状態に復元された後に再開し、プロセスの実行は通常通り続行します。

<img src="../../Document/Images/Chapters/0x04/frida.png" width="100%" />

- _Frida アーキテクチャ, 情報源: [https://www.frida.re/docs/hacking/](https://www.frida.re/docs/hacking "Frida - Hacking")_

Frida には三つの動作モードがあります。

1. Injected: これは frida-server が iOS または Android デバイスでデーモンとして実行されている場合の最も一般的なシナリオです。frida-core は TCP で公開され、デフォルトで localhost:27042 でリッスンします。このモードでの実行は、ルート化や脱獄を行われていないデバイスでは不可能です。
2. Embedded: これはデバイスがルート化や脱獄を行われていない (権限のないユーザーとして ptrace を使用できない) 場合です。あなたには手作業で、または [objection](MASTG-TOOL-0038.md) などのサードパーティツールを介して、アプリに [frida-gadget](https://www.frida.re/docs/gadget/ "Frida Gadget") ライブラリを埋め込むことにより、インジェクションを行う責任があります。
3. Preloaded: `LD_PRELOAD` や `DYLD_INSERT_LIBRARIES` に似ています。frida-gadget を自律的に実行し、ファイルシステム (Gadget バイナリが存在する場所への相対パスなど) からスクリプトをロードするように設定できます。

選択したモードに関係なく、[Frida JavaScript API](https://www.frida.re/docs/javascript-api/ "Frida JavaScript APIs") を使用して、実行中のプロセスおよびそのメモリとやり取りできます。基本的な API には以下のものがあります。

- [Interceptor](https://www.frida.re/docs/javascript-api/#interceptor "Interceptor"): Interceptor API を使用する場合、Frida は関数のプロローグにトランポリン (別名インラインフック) を注入します。これはカスタムコードへのリダイレクトを引き起こし、コードを実行して、元の関数に戻ります。私たちの目的には非常に効果的ですが、これはかなりのオーバーヘッド (トランポリンに関連したジャンプとコンテキストスイッチによる) をもたらし、元のコードを上書きしてデバッガと同様に動作 (ブレークポイントの設定) を行うため、透過的であるとはみなすことはできず、たとえば定期的に独自のコードのチェックサムを行うアプリケーションによって、同様の方法で検出される可能性があることに注意してください。
- [Stalker](https://www.frida.re/docs/javascript-api/#stalker "Stalker"): トレースの要件に透明性、パフォーマンス、高い粒度を含む場合には、Stalker が選択すべき API です。Stalker API でコードをトレースする場合、Frida はジャストインタイムの動的再コンパイルを ([Capstone](http://www.capstone-engine.org/ "Capstone") を使用して) 活用します。スレッドが次の命令を実行しようとすると、Stalker はメモリを割り当て、オリジナルのコードをコピーし、計装のためにそのコピーをカスタムコードとインタレースします。最後に、そのコピーを実行します (オリジナルのコードはそのままにしておくので、アンチデバッグチェックは回避します)。このアプローチは計装のパフォーマンスを大幅に向上し、トレース時に非常に高い粒度を可能にします (CALL または RET 命令のみをトレースするなど)。より詳細については [Frida の作者 Ole によるブログ投稿 "Anatomy of a code tracer"](https://medium.com/@oleavr/anatomy-of-a-code-tracer-b081aadb0df8 "Anatomy of a code tracer") [#vadla] をご覧ください。Stalker の使用例としては [who-does-it-call](https://codeshare.frida.re/@oleavr/who-does-it-call/ "who-does-it-call") や [diff-calls](https://github.com/frida/frida-presentations/blob/master/R2Con2017/01-basics/02-diff-calls.js "diff-calls") などがあります。
- [Java](https://www.frida.re/docs/javascript-api/#java "Java"): Android で作業する場合、この API を使用して、ロードされたクラスを列挙したり、クラスローダーを列挙したり、特定のクラスインスタンスを作成して使用したり、ヒープをスキャンしてクラスのライブインスタンスを列挙することなどができます。
- [ObjC](https://www.frida.re/docs/javascript-api/#objc "ObjC"): iOS で作業する場合、この API を使用して、登録されているすべてのクラスのマッピングを取得したり、特定のクラスやプロトコルのインスタンスを登録または使用したり、ヒープをスキャンしてクラスのライブインスタンスを列挙することなどができます。

また Frida は Frida API 上に構築されたシンプルなツールもいくつか提供しており、pip 経由で frida-tools をインストールした後、ターミナルからすぐに利用できます。たとえば、以下があります。

- [Frida CLI](https://www.frida.re/docs/frida-cli/ "Frida CLI") (`frida`) を使用して、スクリプトのプロトタイピングや試行錯誤のシナリオをすばやく実行できます。
- [`frida-ps`](https://www.frida.re/docs/frida-ps/ "frida-ps") はデバイス上で動作しているすべてのアプリ (またはプロセス) の名前、識別子、PID を含むリストを取得します。
- [`frida-ls-devices`](https://www.frida.re/docs/frida-ls-devices/ "frida-ls-devices") は Frida サーバーやエージェントを実行している接続されたデバイスをリストします。
- [`frida-trace`](https://www.frida.re/docs/frida-trace/ "frida-trace") は iOS アプリの一部であるメソッド、または Android ネイティブライブラリ内に実装されているメソッドをすばやくトレースします。

さらに、以下のようなオープンソースの Frida ベースのツールもいくつかあります。

- [Grapefruit](../ios/MASTG-TOOL-0061.md): iOS 用のランタイムアプリケーション計装ツールキット。
- [Fridump](MASTG-TOOL-0106.md): Android と iOS の両方に対応したメモリダンプツール。
- [objection](MASTG-TOOL-0038.md): ランタイムモバイルセキュリティ評価フレームワーク。
- [r2frida](MASTG-TOOL-0036.md): 強力な radare2 のリバースエンジニアリング機能と Frida の動的計装ツールキットを統合したプロジェクト。
- [JNITrace](MASTG-TOOL-0107.md): ネイティブライブラリによる Android JNI ランタイムメソッドの使用を追跡するツール。

ガイド全体でこれらのツールをすべて使用します。

これらのツールはそのまま使用することも、ニーズに合わせて調整することも、API の使用方法に関する優れた例とすることもできます。例としてこれらを使用すると、独自のフックスクリプトを作成するときや、リバースエンジニアリングワークフローをサポートするイントロスペクションツールを構築するときに非常に役立ちます。
