---
title: Frida
platform: generic
source: https://github.com/frida/frida
---

[Frida](https://www.frida.re "Frida") は Ole André Vadla Ravnås によって書かれたフリーでオープンソースの動的コード計装ツールキットで、[QuickJS](https://bellard.org/quickjs/) JavaScript エンジン (以前は [Duktape](https://duktape.org/ "Duktape JavaScript Engine") と [V8](https://v8.dev/docs "V8 JavaScript Engine")) を計装されたプロセスに注入することで機能します。Frida は Android と iOS (および [その他のプラットフォーム](https://www.frida.re/docs/home/ "So what is Frida, exactly?")) のネイティブアプリで JavaScript のスニペットを実行できます。

<img src="../../Document/Images/Chapters/0x04/frida_logo.png" style="width: 80%; border-radius: 5px; margin: 2em" />

## インストール

Frida をローカルにインストールするには、以下を実行するだけです。

```bash
pip install frida-tools
```

また詳細については [インストールページ](https://www.frida.re/docs/installation/ "Frida Installation") を参照してください。

## 動作モード

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

## API

選択したモードに関係なく、[Frida JavaScript API](https://www.frida.re/docs/javascript-api/ "Frida JavaScript APIs") を使用して、実行中のプロセスおよびそのメモリとやり取りできます。基本的な API には以下のものがあります。

- [Interceptor](https://www.frida.re/docs/javascript-api/#interceptor "Interceptor"): Interceptor API を使用する場合、Frida は関数のプロローグにトランポリン (別名インラインフック) を注入します。これはカスタムコードへのリダイレクトを引き起こし、コードを実行して、元の関数に戻ります。私たちの目的には非常に効果的ですが、これはかなりのオーバーヘッド (トランポリンに関連したジャンプとコンテキストスイッチによる) をもたらし、元のコードを上書きしてデバッガと同様に動作 (ブレークポイントの設定) を行うため、透過的であるとはみなすことはできず、たとえば定期的に独自のコードのチェックサムを行うアプリケーションによって、同様の方法で検出される可能性があることに注意してください。
- [Stalker](https://www.frida.re/docs/javascript-api/#stalker "Stalker"): トレースの要件に透明性、パフォーマンス、高い粒度を含む場合には、Stalker が選択すべき API です。Stalker API でコードをトレースする場合、Frida はジャストインタイムの動的再コンパイルを ([Capstone](http://www.capstone-engine.org/ "Capstone") を使用して) 活用します。スレッドが次の命令を実行しようとすると、Stalker はメモリを割り当て、オリジナルのコードをコピーし、計装のためにそのコピーをカスタムコードとインタレースします。最後に、そのコピーを実行します (オリジナルのコードはそのままにしておくので、アンチデバッグチェックは回避します)。このアプローチは計装のパフォーマンスを大幅に向上し、トレース時に非常に高い粒度を可能にします (CALL または RET 命令のみをトレースするなど)。より詳細については [Frida の作者 Ole によるブログ投稿 "Anatomy of a code tracer"](https://medium.com/@oleavr/anatomy-of-a-code-tracer-b081aadb0df8 "Anatomy of a code tracer") [#vadla] をご覧ください。Stalker の使用例としては [who-does-it-call](https://codeshare.frida.re/@oleavr/who-does-it-call/ "who-does-it-call") や [diff-calls](https://github.com/frida/frida-presentations/blob/master/R2Con2017/01-basics/02-diff-calls.js "diff-calls") などがあります。実用的なチュートリアルと高度な使用パターンについては、[Frida ハンドブックの Stalker セクション](https://learnfrida.info/advanced_usage/#stalker) を参照してください。
- [Java](https://www.frida.re/docs/javascript-api/#java "Java"): Android で作業する場合、この API を使用して、ロードされたクラスを列挙したり、クラスローダーを列挙したり、特定のクラスインスタンスを作成して使用したり、ヒープをスキャンしてクラスのライブインスタンスを列挙することなどができます。
- [ObjC](https://www.frida.re/docs/javascript-api/#objc "ObjC"): iOS で作業する場合、この API を使用して、登録されているすべてのクラスのマッピングを取得したり、特定のクラスやプロトコルのインスタンスを登録または使用したり、ヒープをスキャンしてクラスのライブインスタンスを列挙することなどができます。

### Frida 17

Frida 17 では、バンドルされていたランタイムブリッジの削除やいくつかのネイティブ API の変更など、[重大な変更](https://frida.re/news/2025/05/17/frida-17-0-0-released/) をもたらしています。

**ブリッジ:**

Frida 17 では Frida の GumJS ランタイム内にバンドルされていた [ランタイムブリッジ](https://frida.re/docs/bridges/) (`frida-{objc,swift,java}-bridge`) を削除しています。`frida`, `frida-trace`, [Frooky](MASTG-TOOL-0145.md) などの CLI ツールを使用する場合、Java, Objective-C, Swift ブリッジが事前にバンドルされているため、これは目立った影響はなく、これまで通り使用できます。

但し、これらのブリッジに依存する独自の Frida ベースのツールやスクリプトを作成している場合、Frida のパッケージマネージャである `frida-pm` を介して個別にインストールする必要があります。たとえば、Java ブリッジをインストールするには、以下を実行します。

```bash
frida-pm install frida-java-bridge
```

それから、スクリプト内で以下のようにブリッジをインポートして使用できます。

```js
import JavaBridge from 'frida-java-bridge';
JavaBridge.load();
```

独自のツール (カスタム Python スクリプトなど) から Frida でスクリプトを実行する前に、`frida-compile` を使用してスクリプトを必要なブリッジにバンドルする必要があります。

```bash
npx frida-compile -o agent.js -o _agent.js
```

**API の変更:**

Frida はネイティブ API に変更を加えました。これらの変更により既存のスクリプトの一部が動作しなくなる可能性がありますが、より読みやすくパフォーマンスの高いコードを書くことができるようになります。[MASTG Frida スクリプト作成ガイド](https://mas.owasp.org/contributing/writing-content/mastg-frida-scripts.instructions#use-and-validation-of-frida-apis) の完全な概要を参照してください。

たとえば、`Process.enumerateModules()` は `Module` オブジェクトの配列を返すようになり、それらを直接操作できるようになりました。

```js
for (const module of Process.enumerateModules()) {
  console.log(module.name);
}
```

削除されたもう一つの API は `Module.getSymbolByName` で、これは多くのスクリプトで使用されています。シンボルがどのモジュールにあるか分かっているかどうかに応じて、以下の二つの代替手段のいずれかを使用できます。

```js
// If you know the module
Process.getModuleByName('libc.so').getExportByName('open')

// If you don't (i.e., the old Module.getSymbolByName(null, 'open'); )
Module.getGlobalExportByName('open');
```

詳細については、以下を参照してください。

- [Frida 17.0.0 リリースノート](https://frida.re/news/2025/05/17/frida-17-0-0-released/)
- [更新された Frida JavaScript API ドキュメント](https://frida.re/docs/javascript-api/)
- [frida-gum 型定義](https://raw.githubusercontent.com/DefinitelyTyped/DefinitelyTyped/refs/heads/master/types/frida-gum/index.d.ts)

## ツール

また Frida は Frida API 上に構築されたシンプルなツールもいくつか提供しており、pip 経由で frida-tools をインストールした後、ターミナルからすぐに利用できます。たとえば、以下があります。

- [`frida`](https://www.frida.re/docs/frida-cli/ "Frida CLI"): スクリプトのプロトタイピングや試行錯誤のシナリオのための Frida CLI です。
- [`frida-ps`](https://www.frida.re/docs/frida-ps/ "frida-ps"): デバイス上で動作しているすべてのプロセス (アプリ) の名前、識別子、PID などをリストします。
- [`frida-ls-devices`](https://www.frida.re/docs/frida-ls-devices/ "frida-ls-devices"): Frida サーバーやエージェントを実行している接続されたデバイスをリストします。
- [`frida-trace`](https://www.frida.re/docs/frida-trace/ "frida-trace"): Frida スクリプトを書くことなく関数呼び出しをトレースします。

さらに、以下のようなオープンソースの Frida ベースのツールもいくつかあります。

- [Grapefruit](../ios/MASTG-TOOL-0061.md): iOS 用のランタイムアプリケーション計装ツールキット。
- [Fridump](MASTG-TOOL-0106.md): Android と iOS の両方に対応したメモリダンプツール。
- [objection](MASTG-TOOL-0038.md): ランタイムモバイルセキュリティ評価フレームワーク。
- [r2frida](MASTG-TOOL-0036.md): 強力な radare2 のリバースエンジニアリング機能と Frida の動的計装ツールキットを統合したプロジェクト。
- [JNITrace](MASTG-TOOL-0107.md): ネイティブライブラリによる Android JNI ランタイムメソッドの使用を追跡するツール。

ガイド全体でこれらのツールをすべて使用します。

これらのツールはそのまま使用することも、ニーズに合わせて調整することも、API の使用方法に関する優れた例とすることもできます。例としてこれらを使用すると、独自のフックスクリプトを作成するときや、リバースエンジニアリングワークフローをサポートするイントロスペクションツールを構築するときに非常に役立ちます。

## Frida Handbook

[Frida Handbook](https://learnfrida.info/) は MASTG の Dynamic Binary Instrumentation (DBI) テスト技法を拡張した包括的なリソースであり、モバイルセキュリティテストで Frida を使用するための詳細なチュートリアルと実用的な例があります。

このハンドブックは以下を含む幅広いトピックをカバーしています。

- **はじめに**: インストール、基本セットアップ、さまざまなプラットフォームでの最初の Frida スクリプトの実行。
- **コアコンセプト**: Frida のアーキテクチャ、JavaScript API の基礎、ラピッドプロトタイピングに Frida REPL を効果的に使用する方法の理解。
- **フックテクニック**: Android (Java/Kotlin および JNI) と iOS (Objective-C および Swift) にわたる関数、メソッド、ネイティブコードを傍受するための包括的なガイド。
- **メモリ解析**: プロセスメモリの読み取り、書き込み、検索、およびポインタとデータ構造の操作のためのテクニック。
- **高度な使用法**: [コードトレース用の Stalker](https://learnfrida.info/advanced_usage/#stalker)、カスタム計装パターン、パフォーマンス最適化などの高度な機能の詳細な説明。
- **ツールの統合**: Frida を [r2frida](https://learnfrida.info/r2frida/) などの他のセキュリティツールを使用して、radare2 のリバースエンジニアリング機能と Frida の動的計装を組み合わせます。
- **iOS 固有のトピック**: Objective-C ランタイム、Swift の内部、脱獄検出のバイパス、iOS システムフレームワークの計装との連携。
- **Android 固有のトピック**: Java/Kotlin コードの計装、ネイティブライブラリとの連携、ルート検出のバイパス、Android フレームワークコンポーネントの解析。
- **実用的な例**: よくあるモバイルセキュリティテストの課題を解決する方法を示す実際のシナリオとケーススタディ。

Frida Handbook は MASTG の優れた手引きとして機能し、このガイドで説明されているテスト方法論を補完する詳細な説明とハンズオンの例を提供します。
