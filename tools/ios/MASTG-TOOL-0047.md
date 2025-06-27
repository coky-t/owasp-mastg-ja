---
title: Cydia
platform: ios
source: https://cydia.saurik.com/
status: deprecated
deprecation_note: Dopamine や palera1n といった現代の脱獄では、Sileo や Zebra といった現代のパッケージマネージャを使用します。Cydia は iOS 14 以降、意味のあるアップデートを受けておらず、最新の脱獄にはもはや適していません。
covered_by: [MASTG-TOOL-0064]
---

Cydia は Jay Freeman (別名 "saurik") が開発した脱獄済みデバイス向けの代替アプリストアです。グラフィカルユーザーインタフェースと Advanced Packaging Tool (APT) のバージョンを提供します。Cydia を通じて多くの「非承認」アプリパッケージに簡単にアクセスできます。ほとんどの脱獄では Cydia を自動的にインストールします。

脱獄済みデバイス上の多くのツールは Cydia を使用してインストールできます。Cydia は iOS デバイス用の非公式アプリストアであり、リポジトリを管理できます。Cydia では **Sources** -> **Edit** に移動し、左上の **Add** をクリックして、以下のリポジトリを追加すべきです (デフォルトでまだ追加されていない場合)。

- <http://apt.thebigboss.org/repofiles/cydia/>: 最も人気のあるリポジトリの一つが BigBoss で、BigBoss Recommended Tools パッケージなど、さまざまなパッケージを含みます。
- <https://build.frida.re>: Cydia にそのリポジトリを追加して Frida をインストールします。
- <https://repo.chariz.io>: iOS 11 で脱獄を管理するときに便利です。
- <https://apt.bingner.com/>: 優れたツールがいくつかあるもう一つのリポジトリが Elucubratus です。これは Unc0ver を使用して iOS 12 に Cydia をインストールするとインストールされます。

> Sileo App Store を使用している場合、Sileo Compatibility Layer が Cydia と Sileo の間でソースを共有していますが、Cydia は Sileo で追加されたソースを削除できず、[Sileo は Cydia で追加されたソースを削除できない](https://www.idownloadblog.com/2019/01/11/install-sileo-package-manager-on-unc0ver-jailbreak/ "You can now install the Sileo package manager on the unc0ver jailbreak") ことに留意してください。ソースを削除しようとするときは、この点に留意してください。

上記の推奨リポジトリをすべて追加した後、Cydia から以下の便利なパッケージをインストールして開始できます。

- adv-cmds: 高度なコマンドラインです。finger, fingerd, last, lsvfs, md, ps などのツールを含みます。
- AppList: 開発者がインストールされているアプリのリストを照会できるようにし、リストに基づいて設定ペインを提供します。
- Apt: Advanced Package Tool です。DPKG と同様にインストールされているパッケージを管理するために使用できますが、よりフレンドリーに振る舞います。Cydia リポジトリからパッケージをインストール、アンインストール、アップグレード、ダウングレードできます。Elucubratus から提供しています。
- AppSync Unified: 署名されていない iOS アプリケーションを同期およびインストールできます。
- BigBoss Recommended Tools: wget, unrar, less, sqlite3 クライアントなど、iOS にはない標準 Unix ユーティリティを含む、セキュリティテストに役立つ多くのコマンドラインツールをインストールします。
- class-dump: Mach-O に保存されている Objective-C ランタイム情報を調べ、クラスインタフェースを持つヘッダファイルを生成するコマンドラインツールです。
- class-dump-z: Mach-O ファイルに保存されている Swift ランタイム情報を調べ、クラスインタフェースを持つヘッダファイルを生成するコマンドラインツールです。これは Cydia 経由では利用できないため、iOS デバイスで class-dump-z を実行するには [インストール手順](https://iosgods.com/topic/6706-how-to-install-class-dump-z-on-any-64bit-idevices-how-to-use-it/ "class-dump-z installation steps") を参照してください。class-dump-z はメンテナンスされておらず、Swift ではうまく動作しないことに注意してください。代わりに [dsdump](MASTG-TOOL-0048.md) を使用することをお勧めします。
- Clutch: アプリ実行ファイルの復号化に使用します。
- Cycript: インライン化、最適化、Cycript-to-JavaScript コンパイラ、実行中のプロセスに注入できる即時モードのコンソール環境 (Substrate に関連付けられています) です。
- Cydia Substrate: 動的なアプリ操作やイントロスペクションによってサードパーティ iOS アドオンの開発を容易にするプラットフォームです。
- cURL: よく知られた HTTP クライアントであり、デバイスにパッケージをより速くダウンロードするために使用できます。たとえば、デバイスにさまざまバージョンの Frida-server をインストールする必要がある場合に、これは非常に役立ちます。
- Darwin CC Tools: Mach-O ファイルを監査できる nm や strip などの便利なツールセットです。
- IPA Installer Console: コマンドラインから IPA アプリケーションパッケージをインストールするためのツールです。インストール後、`installipa` と `ipainstaller` という二つのコマンドが利用できるようになります。これらは両方とも同じものです。
- Frida: 動的計装に使用できるアプリです。Frida は時間の経過とともに API の実装を変更しているため、一部のスクリプトは特定バージョンの Frida-server でのみ動作するかもしれません (macOS でもバージョンのアップデート/ダウングレードする必要があります)。APT または Cydia 経由でインストールした Frida Server を実行することをお勧めします。その後のアップグレード/ダウングレードは [この Github issue](https://github.com/AloneMonkey/frida-ios-dump/issues/65#issuecomment-490790602 "Resolving Frida version") の手順に従って実行できます。
- Grep: 行をフィルタする便利なツールです。
- Gzip: よく知られている ZIP ユーティリティです。
- PreferenceLoader: Substrate ベースのユーティリティです。開発者が設定アプリケーションにエントリを追加できます。App Store アプリが使用する SettingsBundles に似ています。
- SOcket CAT: ソケットに接続してメッセージを読み書きできるユーティリティです。iOS 12 デバイスで syslog をトレースしたい場合に便利です。

Cydia 以外にも、iOS デバイスに ssh 接続して、たとえば adv-cmds などのパッケージを apt-get 経由で直接インストールすることもできます。

```bash
apt-get update
apt-get install adv-cmds
```
