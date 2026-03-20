---
title: ネイティブコードの逆アセンブル (Disassembling Native Code)
platform: ios
---

Objective-C と Swift は根本的に異なるため、アプリを記述するために使用されるプログラミング言語はリバースエンジニアリングの実現可能性に影響を及ぼします。たとえば、Objective-C は実行時にメソッド呼び出しを変更できます。これは他のアプリ関数へのフック ([Cycript](http://www.cycript.org/ "Cycript") や他のリバースエンジニアリングツールで多用される技法) を容易にします。この "method swizzling" は Swift では異なって実装されており、Objective-C よりも Swift での実装は困難になります。

iOS では、アプリケーションコード (Swift と Objective-C の両方) はすべてマシンコード (ARM など) にコンパイルされます。そのため、iOS アプリケーションを解析するには、逆アセンブラが必要です。

App Store からのアプリケーションを逆アセンブルしたい場合、まず FairPlay DRM を削除します。詳細については [アプリの取得と抽出 (Obtaining and Extracting Apps)](MASTG-TECH-0054.md) を参照してください。

このコンテキストで、「アプリバイナリ」という用語はアプリケーションバンドル内の Mach-O ファイルを指し、コンパイル済みコードを含みます。アプリケーションバンドルの IPA ファイルとは混同してはいけません。IPA ファイルの構成についての詳細は [アプリパッケージの探索 (Exploring the App Package)](MASTG-TECH-0058.md) を参照してください。

## IDA Pro での逆アセンブル

IDA Pro のライセンスをお持ちの場合、IDA Pro でアプリバイナリを解析することもできます。

> 残念ながら IDA のフリー版では ARM プロセッサタイプをサポートしていません。

始めに、IDA Pro でアプリバイナリを開きます。

<img src="Images/Chapters/0x06c/ida_macho_import.png" width="100%" />

ファイルを開くと、IDA Pro は自動解析を実行します。バイナリのサイズによって時間がかかることがあります。自動解析が完了すると、**IDA View** (Disassembly) ウィンドウで逆アセンブリを閲覧したり、**Functions** ウィンドウで関数を探索できます。どちらも以下のスクリーンショットに示されています。

<img src="Images/Chapters/0x06c/ida_main_window.png" width="100%" />

通常の IDA Pro ライセンスはデフォルトでデコンパイラを含んでおらず、Hex-Rays デコンパイラには追加ライセンスを必要とし、高額です。対照的に、Ghidra は高性能でフリーのビルトインデコンパイラを搭載しており、リバースエンジニアリングにおいて魅力的な代替となります。

通常の IDA Pro ライセンスをお持ちで、Hex-Rays デコンパイラを購入したくない場合、IDA Pro 用の [GhIDA プラグイン](https://github.com/Cisco-Talos/GhIDA/) をインストールすることで Ghidra のデコンパイラを使用できます。
