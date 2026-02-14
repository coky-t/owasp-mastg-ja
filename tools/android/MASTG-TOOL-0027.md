---
title: Xposed
platform: android
source: https://github.com/ElderDrivers/EdXposed
status: deprecated
deprecation_note: Xposed は Android 9 (API レベル 28) では動作しません。しかし、EdXposed にフォークされましたが廃止されており、それから LSPosed にフォークされました。オリジナルの LSPosed は廃止されましたが、利用可能な LSPosed のアクティブなフォークが複数存在します ((LSPosed)[MASTG-TOOL-0149.md] 参照)。
covered_by: [MASTG-TOOL-0020, MASTG-TOOL-0025, MASTG-TOOL-0029, MASTG-TOOL-0140]

---

Xposed は、Android アプリケーションパッケージ (APK) を変更したり再フラッシュすることなく、実行時にシステムやアプリケーションの概観や動作を変更できるフレームワークです。技術的には、Zygote の拡張バージョンであり、新しいプロセスを開始する際に Java コードを実行するための API をエクスポートします。新しくインスタンス化されたアプリのコンテキストで Java コードを実行すると、アプリに属する Java メソッドを解決、フック、オーバーライドできるようになります。Xposed は [reflection](https://docs.oracle.com/javase/tutorial/reflect/ "Reflection Tutorial") を使用して、実行中のアプリを調べて変更します。アプリケーションのバイナリは変更されないため、変更はメモリ内に適用され、プロセスの実行中のみ持続します。

Xposed を使用するには、まずルート化済みデバイスに Xposed フレームワークをインストールする必要があります。モジュールは Xposed Installer アプリからインストールでき、GUI でオンとオフを切り替えることができます。

注: Xposed フレームワークのプレーンインストールは SafetyNet で簡単に検出されるため、Magisk を使用して Xposed をインストールすることをお勧めします。そうすることで、SafetyNet 認証を持つアプリケーションは Xposed モジュールでテストできる可能性が高くなります。

Xposed は Frida と比較されてきました。ルート化済みデバイスで Frida を実行すると、同様に効果的なセットアップになります。どちらのフレームワークも動的計装を行いたい場合に多くの価値を提供します。Frida がアプリをクラッシュする場合は、Xposed で同様のことを試すことができます。次に、Frida スクリプトの豊富さと同様に、Xposed に付属する多くのモジュールの一つを簡単に使用できます。たとえば、前に説明した SSL ピン留めをバイパスするモジュール ([JustTrustMe](https://github.com/Fuzion24/JustTrustMe "JustTrustMe") や [SSLUnpinning](https://github.com/ac-pm/SSLUnpinning_Xposed "SSL Unpinning")) などです。Xposed は、[Inspeckage](https://github.com/ac-pm/Inspeckage "Inspeckage") など、他のモジュールも含み、より詳細なアプリケーションテストを行うこともできます。そのうえ、Android アプリケーションでよく使われるセキュリティメカニズムにパッチを適用するために、独自のモジュールを作成することもできます。
