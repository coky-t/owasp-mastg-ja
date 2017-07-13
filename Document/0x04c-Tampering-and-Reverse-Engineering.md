## 改竄とリバースエンジニアリング

モバイルアプリのコンテキストでは、リバースエンジニアリングはコンパイルされたアプリを解析するプロセスであり、内部の動作に関する知識を抽出します。それはバイトコードやバイナリコードから元のソースコードを再構築することに似ていますが、そっくりそのままである必要はありません。リバースエンジニアリングの主な目標はコードを *理解すること* です。

*改竄* はモバイルアプリ (コンパイルされたアプリ、または実行中のプロセス) またはその動作に影響を与える環境を変更するプロセスです。 例えば、アプリがルート化されたテストデバイス上での実行を拒否する可能性があるため、テストの一部を実行できなくなる可能性があります。そのような場合は、特定の動作を変更する必要があります。

リバースエンジニアリングと改竄の技法はクラッカー、改造者、マルウェア解析者、その他のよりエキゾチックな職業の領域に長く属していました。「伝統的な」セキュリティテスト技術者や研究者にとって、リバースエンジニアリングは補完的で、あると便利な種類のスキルですが、日々の業務の 99% において有用ではありませんでした。しかし、状況は一変します。モバイルアプリのブラックボックステストではコンパイルされたアプリを逆アセンブルし、パッチを適用し、バイナリコードやライブプロセスを改竄するテスト担当者がますます必要になっています。多くのモバイルアプリが歓迎されない改竄に対する防御を実装しているという事実は、私たちにとってより簡単なものにはなりません。

モバイルセキュリティテスト技術者は基本的なリバースエンジニアリングの概念を理解できる必要があります。言うまでもなく、モバイルデバイスやオペレーティングシステムも十分に知る必要があります。プロセッサアーキテクチャ、実行形式、プログラミング言語の複雑さなどがあります。

リバースエンジニアリングは芸術であり、利用可能なすべてのファセットがライブラリ全体を占めると説明しています。技術の範囲と専門化の可能性は驚異的です。マルウェア解析の自動化や新しい逆難読化手法の開発など、非常に特殊で独立した部分問題の取り組みに何年も費やすことがあります。セキュリティテスト技術者はジェネラリストです。有能なリバースエンジニアであるためには、膨大な量の情報をフィルタして、実行可能な方法論を構築する必要があります。

常に機能する一般的なリバースエンジニアリングプロセスはありません。それでは、よく使われる手法やツールをについて説明した後で、最も一般的な防御に取り組む例を挙げます。

### あなたがそれを必要とする理由

モバイルセキュリティテストには以下のいくつかの理由から少なくとも基本的なリバースエンジニアリングのスキルを要求されます。

**1. モバイルアプリのブラックボックステストを可能にするため。** 現在のアプリは動的解析を行う能力を妨げる技術的なコントロールを採用することがよくあります。SSL ピンニングとエンドツーエンド (E2E) 暗号化により、プロキシを使用してトラフィックを傍受または操作できないことがあります。ルート検出はアプリがルート化されたデバイスで実行できなくなるため、高度なテストツールを使用することができなくなる可能性があります。この場合には、これらの防御を無効にする必要があります。

**2. ブラックボックスセキュリティテストの静的解析を強化するため。** ブラックボックステストでは、アプリのバイトコードやバイナリコードの静的解析はアプリが何をしているかをよりよく理解するのに役立ちます。また、アプリ内にハードコードされた資格情報など、特定の欠陥を識別することもできます。

**3. リバースエンジニアリングに対する耐性を評価するため。** MASVS-R にリストされているソフトウェア保護対策を実装しているアプリはある程度のリバースエンジニアリングに対して耐性を持つ必要があります。この場合、リバースエンジニアリング防御のテスト (「耐性評価」) はセキュリティテスト全体の一部です。耐性評価では、テスト技術者はリバースエンジニアの役割を引き受け、防御をバイパスすることを試みます。

私たちはモバイルアプリのリバーシングの世界に飛び込む前に、よいニュースと悪いニュースを共有しています。よいニュースからはじめましょう。

**最終的に、リバースエンジニアが常に勝ちます。**

これはモバイルの世界ではよりいっそう真実です。リバースエンジニアは本質的な利点を持っています。モバイルアプリをデプロイおよびサンドボックス化する方法は設計上より制約があるため、Windows ソフトウェア (DRM システムなど) でよく見られるルートキットのような機能を含めることは簡単ではありません。少なくとも Android では、モバイル OS をより高度にコントロールできるため、さまざまな状況で簡単に勝利できます (その力の使い方を知っていると仮定します) 。iOS ではほとんどコントロールできませんが、防御オプションはより制限されます。

悪いニュースとしては、マルチスレッドのアンチデバッグコントロール、暗号化ホワイトボックス、隠れた耐タンパ性機能、非常に複雑なコントロールフロー変換を扱うことは臆病者向きではないということです。最も効果的なソフトウェア保護スキームは非常に独占的であり、標準の微調整やトリックを使用してごまかすことはありません。それらを打ち破るには面倒な手動解析、コーディング、フラストレーション、そして - あなたの人格に応じて - 眠れない夜と緊張状態の関係が要求されます。

最初にその膨大な範囲に圧倒されることはよくあります。始める際の最善の方法は、いくつかの基本的なツール (Android および iOS リバーシングの章の各セクションを参照) をセットアップして、簡単なリバーシングタスクや crackme を開始することです。進むにつれ、アセンブラやバイトコード言語、問題になっているオペレーティングシステム、遭遇する難読化などについて学ぶ必要があります。簡単なタスクから始めて、より難しいものへ徐々にレベルアップします。

以下のセクションでは、モバイルアプリのセキュリティテストで最も良く使用される技法の大まかな概要を説明します。後の章では、Android と iOS の両方について OS 固有の詳細を掘り下げます。

### 基本的な改竄技法

#### バイナリパッチ適用

*パッチ適用* とはコンパイルされたアプリに変更を加えることを意味します。バイナリ実行形式ファイル内のコード変更、Java バイトコードの改変、リソースの改竄などがあります。モバイルゲームのハッキングシーンで同じプロセスが *MOD 適用* として知られています。パッチはさまざまな方法で適用することができます。アプリの逆コンパイル、編集、再アセンブルから16進エディタでのバイナリファイルの編集に至るまで - なんでもありです (このルールはすべてのリバースエンジニアリングに適用されます) 。有用なパッチの詳細な例について後の章で説明します。

心に留めておくもののひとつとして、最新のモバイル OS はコード署名を厳しく強制することがあります。そのため、従来のデスクトップ環境と同様に改変されたアプリの実行することは簡単ではありません。そう、セキュリティ専門家は90年代にははるかに簡単な人生を送っていました。幸運なことに、あなた自身のデバイスで作業する場合、これは難しいことではありません。つまり改変したコードを実行するには、アプリを再署名するか、デフォルトのコード署名検証機能を無効にする必要があるということです。

#### コードインジェクション

コードインジェクションは非常に強力な技法であり、実行時のプロセスを探索および改変できます。インジェクションプロセスはさまざまな方法で実装されますが、自動化され自由に入手可能で十分に文書化されたツールのおかげで、すべての詳細を知らなくても取得できます。これらのツールは、アプリによりインスタンス化されたライブオブジェクトなどの、プロセスメモリや重要な構造体に直接アクセスできます。また、ロードされたライブラリの解決、メソッドやネイティブ関数のフックなどのための多くの便利なユーティリティ関数があります。プロセスメモリの改竄はファイルにパッチを適用するより検出が難しく、大半の場合に推奨される方法です。

Substrate, Frida, XPosed はモバイル業界で最も広く使用されているフックとコードインジェクションのフレームワークです。この三つのフレームワークは設計の哲学と実装の詳細が異なります。Substrate と Xposed はコードインジェクションやフックに焦点を当てています。一方で Frida は本格的な「動的計装フレームワーク」とすることを目指しており、コードインジェクションと言語バインディング、インジェクト可能な JavaScript VM とコンソールを組み込んでいます。

しかし、Cycript をインジェクトするために Substrate を使用してアプリを計装することもできます。Cycript は Cydia で有名な Saurik が作成したプログラミング環境 (通称 "Cycript-to-JavaScript" コンパイラ) です。さらに物事は複雑になりますが、Frida の作者も "frida-cycript" という名前の Cycript のフォークを作成しました。これは Cycript のランタイムを Mjølner <sup>[1]</sup> と呼ばれる Frida ベースのランタイムに置き換えます。これにより frida-core で維持されているすべてのプラットフォームとアーキテクチャで Cycript を実行できます (混乱しても心配ありません、それで十分 OK です) 。

このリリースは Frida の開発者 Ole による "Cycript on Steroids" というタイトルのブログ記事にあります。Saurik <sup>[2]</sup> ではうまく機能していませんでした。

三つのフレームワークについて例をいくつか紹介します。最初の選択肢として、Frida で始めることをお勧めします。これは三つの中で最も汎用性が高いためです (この理由から、Frida の詳細と事例が多く紹介されています) 。特に、Frida は Android と iOS の両方のプロセスに Javascript VM をインジェクトできます。一方で Substrate での Cycript インジェクションは iOS 上でのみ動作します。しかし最終的には、いずれのフレームワークでも多くの同じ最終目標に到達できます。

### Static and Dynamic Binary Analysis

Reverse engineering is the process of reconstructing the semantics of the original source code from a compiled program. In other words, you take the program apart, run it, simulate parts of it, and do other unspeakable things to it, in order to understand what it is doing and how.

#### Using Disassemblers and Decompilers

Disassemblers and decompilers allow you to translate an app binary code or byte-code back into a more or less understandable format. In the case of native binaries, you'll usually obtain assembler code matching the architecture which the app was compiled for. Android Java apps can be disassembled to Smali, which is an assembler language for the dex format used by dalvik, Android's Java VM. The Smali assembly is also quite easily decompiled back to Java code.

A wide range of tools and frameworks is available: from expensive but convenient GUI tools, to open source disassembling engines and reverse engineering frameworks. Advanced usage instructions for any of these tools often easily fill a book on their own. The best way to get started though is simply picking a tool that fits your needs and budget and buying a well-reviewed user guide along with it. We'll list some of the most popular tools in the OS-specific "Reverse Engineering and Yampering" chapters.

#### Debugging and Tracing

In the traditional sense, debugging is the process of identifying and isolating problems in a program as part of the software development lifecycle. The very same tools used for debugging are of great value to reverse engineers even when identifying bugs is not the primary goal. Debuggers enable suspending a program at any point during runtime, inspect the internal state of the process, and even modify the content of registers and memory. These abilities make it *much* easier to figure out what a program is actually doing.

When talking about debugging, we usually mean interactive debugging sessions in which a debugger is attached to the running process. In contrast, *tracing* refers to passive logging of information about the app's execution, such as API calls. This can be done in a number of ways, including debugging APIs, function hooks, or Kernel tracing facilities. Again, we'll cover many of these techniques in the OS-specific "Reverse Engineering and Yampering" chapters.

### Advanced Techniques

For more complicated tasks, such as de-obfuscating heavily obfuscated binaries, you won't get far without automating certain parts of the analysis. For example, understanding and simplifying a complex control flow graph manually in the disassembler would take you years (and most likely drive you mad, way before you're done). Instead, you can augment your workflow with custom made scripts or tools. Fortunately, modern disassemblers come with scripting and extension APIs, and many useful extensions are available for popular ones. Additionally, open-source disassembling engines and binary analysis frameworks exist to make your life easier.

Like always in hacking, the anything-goes-rule applies: Simply use whatever brings you closer to your goal most efficiently. Every binary is different, and every reverse engineer has their own style. Often, the best way to get to the goal is to combine different approaches, such as emulator-based tracing and symbolic execution, to fit the task at hand. To get started, pick a good disassembler and/or reverse engineering framework and start using them to get comfortable with their particular features and extension APIs. Ultimately, the best way to get better is getting hands-on experience.

#### Dynamic Binary Instrumentation

Another useful method for dealing with native binaries is dynamic binary instrumentations (DBI). Instrumentation frameworks such as Valgrind and PIN support fine-grained instruction-level tracing of single processes. This is achieved by inserting dynamically generated code at runtime. Valgrind compiles fine on Android, and pre-built binaries are available for download.

The Valgrind README contains specific compilation instructions for Android - http://valgrind.org/docs/manual/dist.readme-android.html

#### Emulation-based Dynamic Analysis

Running an app in the emulator gives you powerful ways to monitor and manipulate its environment. For some reverse engineering tasks, especially those that require low-level instruction tracing, emulation is the best (or only) choice. Unfortunately, this type of analysis is only viable for Android, as no emulator for iOS exists (the iOS simulator is not an emulator, and apps compiled for an iOS device don't run on it). We'll provide an overview of popular emulation-based analysis frameworks for Android in the "Tampering and Reverse Engineering on Android" chapter.

#### Custom Tooling using Reverse Engineering Frameworks

Even though most professional GUI-based disassemblers feature scripting facilities and extensibility, they sometimes simply not well-suited to solving a particular problem. Reverse engineering frameworks allow you perform and automate any kind of reversing task without the dependence for heavy-weight GUI, while also allowing for increased flexibility. Notably, most reversing frameworks are open source and/or available for free. Popular frameworks with support for mobile architectures include Radare2<sup>[3]</sup> and Angr <sup>[4]</sup>.

##### Example: Program Analysis using Symbolic / Concolic Execution

In the late 2000s, symbolic-execution based testing has gained popularity as a means of identifying security vulnerabilities. Symbolic "execution" actually refers to the process of representing possible paths through a program as formulas in first-order logic, whereby variables are represented by symbolic values, which are actually entire ranges of values. Satisfiability Modulo Theories (SMT) solvers are used to check satisfiability of those formulas and provide a solution, including concrete values for the variables needed to reach a certain point of execution on the path corresponding to the solved formula.

Typically, this approach is used in combination with other techniques such as dynamic execution (hence the name concolic stems from *conc*rete and symb*olic*), in order to tone down the path explosion problem specific to classical symbolic execution. This together with improved SMT solvers and current hardware speeds, allow concolic execution to explore paths in medium size software modules (i.e. in the order of 10s KLOC). However, it also comes in handy for supporting de-obfuscation tasks, such as simplifying control flow graphs. For example, Jonathan Salwan and Romain Thomas have shown how to reverse engineer VM-based software protections using Dynamic Symbolic Execution (i.e., using a mix of actual execution traces, simulation and symbolic execution)<sup>[5]</sup>.

In the Android section, you'll find a walkthrough for cracking a simple license check in an Android application using symbolic execution.

### 参考情報

* [1] Cycript fork powered by Frida - https://github.com/nowsecure/frida-cycript
* [2] Cycript on steroids: Pumping up portability and performance with Frida - 
* [3] Radare2 - https://github.com/radare/radare2
* [4] Angr - http://angr.io
* [5] https://triton.quarkslab.com/files/csaw2016-sos-rthomas-jsalwan.pdf
