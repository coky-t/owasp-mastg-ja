---
title: Ghidra
platform: generic
source: https://github.com/NationalSecurityAgency/ghidra
---

[Ghidra](https://github.com/NationalSecurityAgency/ghidra) はアメリカ合衆国の国家安全保障局 (NSA) の研究局によって開発されたオープンソースのソフトウェアリバースエンジニアリング (SRE) ツールスイートです。Ghidra は逆アセンブラ、逆コンパイラ、高度な使用のためのビルトインスクリプトエンジンで構成される多目的ツールです。インストール方法については [インストールガイド](https://ghidra-sre.org/InstallationGuide.html "Ghidra Installation Guide") を参照してください。また、[チートシート](https://ghidra-sre.org/CheatSheet.html "Cheat Sheet") を参照して、利用可能なコマンドとショートカットの概要を確認してください。このセクションでは、プロジェクトの作成方法、バイナリの逆アセンブリおよび逆コンパイルされたコードの表示方法について説明します。

Ghidra を起動するには、使用しているプラットフォームに応じて `ghidraRun` (\*nix) または `ghidraRun.bat` (Windows) を使用します。Ghidra を起動したら、プロジェクトディレクトリを指定して新しいプロジェクトを作成します。以下のようなウィンドウが表示されます。

<img src="../../Document/Images/Chapters/0x04c/Ghidra_new_project.png" width="100%" />

新しい **Active Project** でアプリバイナリをインポートするには、**File** -> **Import File** に移動して、目的のファイルを選択します。

<img src="../../Document/Images/Chapters/0x04c/Ghidra_import_binary.png" width="100%" />

ファイルが適切に処理できると、Ghidra は解析を開始する前にそのバイナリに関するメタ情報を表示します。

<img src="../../Document/Images/Chapters/0x04c/Ghidra_elf_import.png" width="100%" />

上記で選択したバイナリファイルの逆アセンブルコードを取得するには、**Active Project** ウィンドウからインポートしたファイルをダブルクリックします。自動解析を行うには後続のウィンドウで **yes** と **analyze** をクリックします。自動解析はバイナリのサイズに応じて時間がかかりますが、進行状況はコードブラウザウィンドウの右下隅で追跡できます。自動解析が完了したら、バイナリの探索を開始できます。

<img src="../../Document/Images/Chapters/0x04c/Ghidra_main_window.png" width="100%" />

Ghidra でバイナリを探索するために最も重要なウィンドウは **Listing** (逆アセンブリ) ウィンドウ、**Symbol Tree** ウィンドウ、**Decompiler** ウィンドウであり、逆アセンブリのために選択された関数の逆コンパイルされたバージョンを表示します。**Display Function Graph** オプションは、選択した関数のコントロールフローグラフを表示します。

<img src="../../Document/Images/Chapters/0x04c/Ghidra_function_graph.png" width="100%" />

Ghidra には他にも多くの機能があり、そのほとんどは **Window** メニューを開くことで探索できます。たとえば、バイナリに存在する文字列を調べたい場合は、**Defined Strings** オプションを開きます。Android と iOS プラットフォームのさまざまなバイナリを解析する際のその他の高度な機能については次の章で説明します。

<img src="../../Document/Images/Chapters/0x04c/Ghidra_string_window.png" width="100%" />
