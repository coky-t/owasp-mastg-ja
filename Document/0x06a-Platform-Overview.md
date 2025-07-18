# iOS プラットフォーム概要

iOS は iPhone, iPad, iPod Touch などの Apple のモバイルデバイスに対応するモバイルオペレーティングシステムです。iOS の多くの機能を継承する Apple tvOS の基礎でもあります。このセクションではアーキテクチャの観点から iOS プラットフォームを紹介します。以下の五つの主要分野について説明します。

1. iOS セキュリティアーキテクチャ
2. iOS アプリケーションの構造
3. プロセス間通信 (IPC)
4. iOS アプリケーションの公開
5. iOS アプリケーション攻撃領域

Apple のデスクトップオペレーティングシステム macOS (以前の OS X) と同様に、Apple により開発されたオープンソースの Unix オペレーティングシステムである Darwin をベースとしています。Darwin のカーネルは XNU ("X is Not Unix") であり、Mach と FreeBSD カーネルのコンポーネントを組み合わせたハイブリッドカーネルです。

しかし、iOS アプリはデスクトップよりも制限された環境で動作します。iOS アプリはファイルシステムレベルで互いに分離されており、システム API アクセスの点で大幅に制限されています。

ユーザーを悪意のあるアプリケーションから保護するために、Apple は iOS デバイス上で実行できるアプリへのアクセスを制限および制御します。Apple の App Store は唯一の公式アプリケーション配信プラットフォームです。開発者はアプリを提供でき、消費者はアプリを購入、ダウンロード、インストールできます。この配信スタイルは Android とは異なり、いくつかのアプリストアおよびサイドローディング (公式の App Store を使用せずに iOS デバイスにアプリをインストールする) をサポートしています。iOS では、サイドローディングは一般的に USB 経由のアプリインストール方法を指しますが、 [Apple Developer Enterprise Program](https://developer.apple.com/programs/enterprise/ "Apple Developer Enterprise Program") の下で App Store を使用しない他の iOS アプリ配布方法があります。

以前は、サイドローディングは脱獄または複雑なワークアラウンドでのみ可能でした。iOS 9 またはそれ以降では、[Xcode 経由でサイドロードする](https://forums.developer.apple.com/forums/thread/91370) ことが可能です。

iOS アプリは Apple の iOS Sandbox (歴史的に Seatbelt と呼ばれている) の、アプリがアクセス可能および不可となるリソースを記述する強制アクセスコントロール (MAC) メカニズムにより互いに分離されています。Android の広範囲の Binder IPC (プロセス間通信) 機能と比較して、iOS は IPC オプションをほとんど提供しないため、潜在的なアタックサーフェイスを最小限に抑えます。

統一されたハードウェアと緊密なハードウェアとソフトウェアの統合はもうひとつのセキュリティのアドバンテージを生み出します。すべての iOS デバイスは (iOS のデータ保護として参照される) セキュアブート、ハードウェア支援のキーチェーン、ファイルシステムの暗号化などのセキュリティ機能を提供します。iOS アップデートは通常すぐにユーザーの大部分に配信され、古く保護されていない iOS バージョンをサポートする必要性が減ります。

iOS には多くの強みがありますが、iOS アプリ開発者はそれでもセキュリティについて心配する必要があります。データ保護、キーチェーン、Touch ID/Face ID 認証、ネットワークセキュリティは依然としてエラーの余地を多く残しています。以下の章では、iOS セキュリティアーキテクチャについて述べ、基本的なセキュリティテスト手法を説明し、リバースエンジニアリングの方法を提供します。

## iOS セキュリティアーキテクチャ

[iOS セキュリティアーキテクチャ](https://www.apple.com/business/docs/iOS_Security_Guide.pdf "Apple iOS Security Guide") は Apple が iOS セキュリティガイドで公式に文書化したもので、六つのコア機能で構成されています。このセキュリティガイドは各メジャー iOS バージョンごとに Apple により更新されています。

- ハードウェアセキュリティ
- セキュアブート
- コード署名
- サンドボックス
- 暗号化とデータ保護
- 汎用的なエクスプロイト緩和策

<img src="Images/Chapters/0x06a/iOS_Security_Architecture.png" width="200px" />

### ハードウェアセキュリティ

iOS セキュリティアーキテクチャは全体的な性能を向上させるハードウェアベースのセキュリティ機能を有効に活用します。各 iOS デバイスには二つの内蔵 Advanced Encryption Standard (AES) 256 ビット鍵が付属しています。デバイスのユニーク ID (UID) とデバイスグループ ID  製造時にアプリケーションプロセッサおよびセキュアエンクレーブに融合されコンパイルされます。デバイスのユニーク ID (UID) とデバイスグループ ID (GID) は、製造時にアプリケーションプロセッサ (AP) およびセキュアエンクレーブ (SEP) に融合 (UID) またはコンパイル (GID) された AES 256 ビット鍵です。ソフトウェアや JTAG などのデバッグインタフェースでこれらの鍵を読む直接的な方法はありません。暗号化および復号化操作は、これらの鍵への排他的アクセスを行うハードウェア AES 暗号エンジンにより実行されます。

GID はデバイスクラス内のすべてのプロセッサで共有される値であり、ユーザーの個人データに直接関係しないファームウェアファイルやその他の暗号化タスクの改竄を防止するために使用されます。各デバイスに固有の UID はデバイスレベルのファイルシステムの暗号化に使用される鍵階層を保護するために使用されます。UID は製造中に記録されないため、Apple でも特定のデバイスのファイル暗号鍵を復元することはできません。

フラッシュメモリの機密データを安全に削除するために、iOS デバイスには [Effaceable Storage](https://www.apple.com/business/docs/iOS_Security_Guide.pdf "iOS Security Guide") という機能があります。この機能はストレージテクノロジへの直接的な低レベルアクセスを提供し、選択されたブロックを安全に消去することを可能にします。

### セキュアブート

iOS デバイスの電源を入れると、ブート ROM として知られる読み取り専用メモリから初期命令を読み込み、システムをブートストラップします。ブート ROM には不変コードと Apple Root CA が含まれています。製造プロセス中にシリコンチップにエッチングされ、それにより信頼されたルートを作成します。次に、ブート ROM は LLB (ローレベルブートローダー) の署名が正しいことを確認し、LLB も iBoot ブートローダーの署名が正しいことを確認します。署名が検証された後、iBoot は iOS カーネルである次のブートステージの署名をチェックします。これらの手順のいずれかが失敗すると、ブートプロセスは直ちに終了し、デバイスはリカバリモードに入り、[restore screen](https://support.apple.com/en-us/HT203122 "If you see the Restore screen on your iPhone, iPad, or iPod touch") を表示します。但し、ブート ROM がロードに失敗した場合、デバイスはデバイスファームウェアアップグレード (DFU) と呼ばれる低レベルリカバリモードに入ります。これはデバイスを元の状態に復元するための最後の手段です。このモードでは、デバイスは動作の兆候を示しません。つまり、画面には何も表示されません。

このプロセス全体を「セキュアブートチェーン」と呼びます。その目的は、ブートプロセスの完全性を検証し、システムとそのコンポーネントが Apple により作成及び配布されていることを保証することに焦点を当てています。セキュアブートチェーンはカーネル、ブートローダー、カーネル拡張、ベースバンドファームウェアで構成されます。

### コード署名

Apple は Apple が承認したコード、つまり Apple により署名されたコードだけがデバイス上で動作するように、精巧な DRM システムを実装しています。言い換えれば、Apple が明示的に許可しない限り、脱獄されていない iOS デバイス上で任意のコードを実行することはできません。エンドユーザーは公式の Apple の App Store を通じてのみアプリをインストールするようになっています。この理由 (およびその他) のために、iOS は [crystal prison とみなされています](https://www.eff.org/deeplinks/2012/05/apples-crystal-prison-and-future-open-platforms "Apple\'s Crystal Prison and the Future of Open Platforms") 。

アプリケーションを配布および実行するには開発者プロファイルと Apple 署名証明書が必要です。
開発者は Apple に登録する必要があります。[Apple Developer Program](https://developer.apple.com/support/compare-memberships/ "Membership for Apple Developer Program") に参加し、年間サブスクリプションを支払うことで開発と配布の可能性を広げます。また、サイドローディングを介してアプリをコンパイルおよび配布できる (但し、App Store では配布できない) フリーの開発者アカウントもあります。

<img src="Images/Chapters/0x06a/code_signing.png" width="400px" />

[アーカイブされた Apple 開発者ドキュメント](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/AboutCS/AboutCS.html#//apple_ref/doc/uid/TP40005929-CH3-SW3) によると、コード署名は三つのパーツで構成されているようです。

- 印章。これはコード署名ソフトウェアによって作成された、コードのさまざまなパーツのチェックサムまたはハッシュのコレクションです。印章は検証時に改竄を検出するために使用できます。
- デジタル署名。コード署名ソフトウェアは署名者の ID を使用して印章を暗号化し、デジタル署名を作成します。これにより印章の完全性が保証されます。
- コード要件。コード署名の検証に関するルールです。目標に応じて、検証者に固有のものもあれば、署名者が指定して、コードの残りの部分と一緒に封印するものもあります。

詳しくはこちら。

- [Code Signing Guide (Archived Apple Developer Documentation)](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Introduction/Introduction.html)
- [Code Signing (Apple Developer Documentation)](https://developer.apple.com/support/code-signing/)
- [Demystifying iOS Code Signature](https://medium.com/csit-tech-blog/demystifying-ios-code-signature-309d52c2ff1d)

### 暗号化とデータ保護

_FairPlay コード暗号化_ は App Store からダウンロードしたアプリに適用されます。FairPlay はマルチメディアコンテンツを購入する際の DRM として開発されました。もともと、FairPlay の暗号化は MPEG や QuickTime ストリームに適用されていましたが、同じ基本概念を実行可能ファイルにも適用できます。基本的な考え方は次の通りです。新しい Apple ユーザーアカウントまたは Apple ID を登録すると、公開鍵と秘密鍵 (private key) のペアが作成され、アカウントに割り当てられます。その秘密鍵 (private key) はデバイス上にセキュアに格納されます。つまり FairPlay で暗号化されたコードはアカウントに関連付けられたデバイス上でのみ復号できます。FairPlay 暗号のリバースは通常、デバイス上でアプリを実行し、メモリから復号されたコードをダンプして取得します (「iOS アプリのテスト環境構築」も参照してください) 。

Apple は iPhone 3GS のリリース以降 iOS デバイスのハードウェアとファームウェアに暗号化を組み込んでいます。すべてのデバイスには AES 256 ビット暗号化と SHA-1 ハッシュアルゴリズムの実装を提供する専用のハードウェアベースの暗号エンジンが搭載されています。それに加えて、これはアプリケーションプロセッサに融合した AES 256 ビット鍵とともに、各デバイスのハードウェアに組み込まれた固有識別子 (UID) があります。この UID は一意であり他には記録されません。執筆時点では、ソフトウェアやファームウェアでは直接読み取ることはできません。鍵はシリコンチップに焼き付けられるため、それを改竄やバイパスすることはできません。暗号エンジンだけがアクセスできます。

物理的なアーキテクチャに暗号化を組み込むことで iOS デバイスに保存されているすべてのデータを暗号化できるデフォルトのセキュリティ機能を実現します。その結果、データ保護はソフトウェアレベルで実装され、ハードウェアとファームウェアの暗号化を使用してセキュリティを強化します。

データ保護が有効な場合、モバイルデバイスにパスコードを設定するだけで、各データファイルは特定の保護クラスに関連付けられます。それぞれのクラスは異なるレベルのアクセシビリティをサポートし、データにアクセスが必要なときに基づいてデータを保護します。各クラスに関連する暗号化および復号化操作は複数の鍵メカニズムに基づいています。デバイスのUID、パスコード、クラス鍵、ファイルシステム鍵、ファイルごとの鍵を使用します。ファイルごとの鍵はファイルの内容を暗号化するために使用されます。クラス鍵はファイルごとの鍵にラップされ、ファイルのメタデータに格納されます。ファイルシステム鍵はメタデータの暗号化に使用されます。UID とパスコードはクラス鍵を保護します。この操作はユーザーには見えません。データ保護を有効にするには、デバイスにアクセスする際にパスコードを使用する必要があります。パスコードはデバイスのロックを解除します。UID と組み合わせることにより、パスコードはハッキングやブルートフォース攻撃により耐性のある iOS 暗号化鍵を作成します。ユーザーがデバイスでパスコードを使用する主な理由はデータ保護を有効にするためです。

### サンドボックス

[アプリサンドボックス](https://developer.apple.com/library/content/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html "File System Basics") は iOS アクセス制御技術です。それはカーネルレベルで実施されています。これはアプリが侵害されたときに発生する可能性のあるシステムやユーザーデータへの損害を制限することを目的としています。

サンドボックスは iOS の最初のリリースから主要なセキュリティ機能です。すべてのサードパーティアプリは同じユーザー (`mobile`) の下で実行されますが、ほんの一部のシステムアプリケーションやサービルは `root` (または他の特定のシステムユーザー) として実行されます。ファイル、ネットワークソケット、IPC、共有メモリなどのすべてのリソースへのアクセスはサンドボックスによってコントロールされます。通常の iOS アプリは _コンテナ_ に限定されています。アプリ自身のファイルへのアクセスと非常に限られた数のシステム API に制限されています。すべてのリソース (ファイル、ネットワークソケット、IPC、共有メモリなど) へのアクセスはサンドボックスにより制御されています。これらの制限は以下のように機能します。 [#levin]

- アプリプロセスは chroot のようなプロセスを介して自身のディレクトリ (/var/mobile/Containers/ Bundle/Application/ または /var/containers/Bundle/Application/ の下、iOS バージョンに依存します) に制限されています。
- `mmap` および `mmprotect` システムコールは修正されています。アプリが書き込み可能なメモリページを実行可能にすることを防ぎ、動的に生成されたコードを実行するプロセスを停止します。コード署名と FairPlay を組み合わせることで、特定の条件下で実行できるコードを厳しく制限します (例えば、App Store を介して配布されるアプリ内のすべてのコードは Apple により承認されています) 。
- プロセスはオペレーティングシステムレベルで同じ UID により所有されているとしても、互いに分離されています。
- ハードウェアドライバに直接的にアクセスすることはできません。代わりに、Apple の公開フレームワークを通じてアクセスする必要があります。

### 汎用的なエクスプロイト緩和策

iOS はアドレス空間配置のランダム化 (ASLR) と eXecute Never (XN) ビットを実装してコード実行攻撃を軽減しています。

ASLR は、プログラムが実行されるごとに、プログラムの実行可能ファイル、データ、ヒープ、スタックのメモリ位置をランダム化します。共有ライブラリは複数のプロセスがアクセスするために静的である必要があるため、プログラムが呼び出されるごとではなく、OS がブートするごとに共有ライブラリのアドレスはランダム化されます。これにより、特定の関数やライブラリのメモリアドレスを予測することが難しくなり、基本的な libc 関数のメモリアドレスに関わる return-to-libc 攻撃などの攻撃を防ぎます。

XN メカニズムにより iOS はプロセスの選択されたメモリセグメントを実行不可とマークできます。iOS では、ユーザーモードプロセスのプロセススタックとヒープには実行不可とマークされます。書き込み可能であるページには同時に実行可能とマークすることはできません。これにより攻撃者がスタックやヒープに注入したマシンコードを実行することを防ぎます。

## iOS でのソフトウェア開発

他のプラットフォームと同様に、Apple は iOS 向けのソフトウェア開発キット (SDK) を提供しています。開発者がネイティブ iOS アプリを開発、インストール、実行、テストするのに役立ちます。Xcode は Apple ソフトウェア開発のための統合開発環境 (IDE) です。iOS アプリケーションは Objective-C もしくは Swift で開発されます。

Objective-C は Smalltalk スタイルのメッセージングを C 言語に追加したオブジェクト指向プログラミング言語で、macOS でのデスクトップアプリケーションを開発するために、また iOS でのモバイルアプリケーションを開発するために使用されます。Swift は Objective-C の後継であり、Objective-C との相互運用が可能です。

Swift は2014年に Xcode 6 で導入されました。

非脱獄デバイスでは、App Store の外でアプリケーションをインストールするには二つの方法があります。

1. エンタープライズモバイルデバイス管理を介します。これには Apple が署名した会社レベルの証明書が必要です。
2. サイドローディングを介します。すなわち、開発者の証明書でアプリに署名し、Xcode (または Cydia Impactor) 経由でデバイスにインストールします。限られた数のデバイスに同じ証明書でインストールできます。

## iOS でのアプリ

iOS アプリは IPA (iOS App Store Package) アーカイブで配布されています。この IPA ファイルは ZIP 圧縮されたアーカイブであり、アプリを実行するために必要なコードとリソースをすべて含んでいます。

IPA ファイルにはビルトインのディレクトリ構造を持っています。以下の例はこの構造を上位レベルで示しています。

- `/Payload/` フォルダにはすべてのアプリケーションデータが格納されています。このフォルダの内容を更に詳しく説明します。
- `/Payload/Application.app` にはアプリケーションデータ自体 (ARM コンパイルされたコード) と関連する静的リソースが格納されています。
- `/iTunesArtwork` はアプリケーションのアイコンとして使用される 512x512 ピクセルの PNG 画像です。
- `/iTunesMetadata.plist` には開発者の名前とID、バンドルID、著作権情報、ジャンル、アプリ名、リリース日、購入日など、さまざまな情報が格納されています。
- `/WatchKitSupport/WK` は extension バンドルの一例です。この固有のバンドルには Apple Watch でのインタフェースを管理およびユーザーインタラクションに応答する extension delegate とコントローラが含まれています。

### IPA ペイロードの詳細

IPA コンテナ内のさまざまなファイルを詳しく見てみましょう。Apple はディスクスペースを節約しファイルへのアクセスを簡素化するために、余計なディレクトリがほとんどない比較的フラットな構造を採用しています。最上位のバンドルディレクトリにはアプリケーションの実行可能ファイルとアプリケーションが使用するすべてのリソース 最上位のバンドルディレクトリにはアプリケーションの実行可能ファイルとアプリケーションが使用するすべてのリソース (アプリケーションアイコン、その他のイメージ、ローカライズされたコンテンツなど) があります。

- **MyApp**: 実行可能ファイルです。コンパイルされた (読み取り可能ではない) アプリケーションソースコードを含みます。
- **Application**: アプリケーションアイコンです。
- **Info.plist**: 構成情報です。バンドル ID、バージョン番号、アプリケーション表示名などがあります。
- **Launch images**: 特定の向きでのアプリケーションの初期インタフェースを示す画像です。システムはアプリケーションが完全にロードされるまで、提供された起動画像を一時的な背景として使用します。
- **MainWindow.nib**: アプリケーション起動時にロードされるデフォルトのインタフェースオブジェクトです。他のインタフェースオブジェクトは他の nib ファイルからロードされるか、アプリケーションによりプログラムで作成されます。
- **Settings.bundle**: 設定アプリで表示されるアプリケーション固有のプリファレンスです。
- **Custom resource files**: ローカライズされていないリソースは最上位ディレクトリに配置され、ローカライズされたリソースはアプリケーションバンドルの言語固有のサブディレクトリに配置されます。リソースには nib ファイル、画像、音声ファイル、構成ファイル、文字列ファイル、およびアプリケーションが使用するその他のカスタムデータがあります。

language.lproj フォルダはアプリケーションがサポートする言語ごとに定義されています。これにはストーリーボードと文字列ファイルを含んでいます。

- ストーリーボードは iOS アプリケーションのユーザーインタフェースの視覚的な表現です。スクリーンと、スクリーン間の接続を示しています。
- 文字列ファイル形式は一つ以上のキー・バリューのペアとオプションのコメントで構成されています。

<img src="Images/Chapters/0x06a/iOS_project_folder.png" width="400px" />

脱獄済みデバイスでは、メインのアプリバイナリを復号し IPA ファイルの再構築を可能にするさまざまなツールを使用して、インストールされた iOS アプリの IPA を復元できます。同様に、脱獄済みデバイスでは [ipainstaller](../tools/ios/MASTG-TOOL-0138.md) を使用して IPA ファイルをインストールできます。モバイルセキュリティアセスメントでは、開発者が IPA を直接提供することがよくあります。あなたに実際のファイルを送ったり、[TestFlight](https://developer.apple.com/testflight/ "TestFlight") や [Visual Studio App Center](https://appcenter.ms/ "Visual Studio App Center") などの開発用配布プラットフォームへのアクセスを提供することがあります。

### アプリパーミッション

Android アプリ (Android 6.0 (API level 23) 以前) とは異なり、iOS アプリは事前に割り当てられたパーミッションを持ちません。代わりに、アプリが初めてセンシティブな API を使用しようとした際に、実行時にパーミッションを与えるようユーザーに求めます。パーミッションを付与されたアプリは 設定 > プライバシー メニューに表示され、ユーザーはアプリ固有の設定を変更できます。Apple はこのパーミッションコンセプト [プライバシー管理](https://support.apple.com/en-sg/HT203033 "Apple - About privacy and Location Services in iOS 8 and later") を呼び出します。

iOS 開発者はパーミッションを直接設定することはできません。センシティブな API にアクセスする際に間接的に要求されます。例えば、ユーザーの連絡先にアクセスすると、ユーザーがアクセスを許可または拒否するよう求められている間、CNContactStore へのコールはアプリをブロックします。iOS 10.0 以降、アプリは要求するパーミッションのタイプとアクセスする必要があるデータについて usage description キーを含む必要があります (NSContactsUsageDescription など)。

以下の API は [ユーザーパーミッションを必要とします](https://www.apple.com/business/docs/iOS_Security_Guide.pdf "iOS Security Guide. Page 62") 。

- Contacts
- Microphone
- Calendars
- Camera
- Reminders
- HomeKit
- Photos
- Health
- Motion activity and fitness
- Speech recognition
- Location Services
- Bluetooth sharing
- Media Library
- Social media accounts

### DeviceCheck

DeviceCheck フレームワークは DeviceCheck および App Attest のコンポーネントを含み、サービスの不正使用防止を支援します。DeviceCheck フレームワークはアプリから使用するフレームワークと、独自のサーバーにのみアクセスできる Apple サーバーで構成しています。DeviceCheck では情報をデバイスと Apple サーバーに永続的に保存できます。保存された情報は、アプリの再インストール、デバイス転送、リセット後もそのまま残りますが、このデータを定期的にリセットするオプションもあります。

DeviceCheck は一般的に機密リソースへのアクセスを制限することで不正行為を制限するために使用されます。たとえば、プロモーションをデバイスごとに一回に制限する、不正なデバイスを特定してフラグを立てるなどです。ただし、すべての不正を防ぐことはできません。たとえば、これは [侵害されたオペレーティングシステムを検出するもの (別名、脱獄検出) ではありません](https://swiftrocks.com/app-attest-apple-protect-ios-jailbreak "App Attest: How to prevent an iOS app's APIs from being abused") 。

詳細については [DeviceCheck ドキュメント](https://developer.apple.com/documentation/devicecheck "DeviceCheck documentation") を参照してください。

#### App Attest

DeviceCheck フレームワークで利用できる App Attest は、ハードウェア支援のアサーションをリクエストにアタッチできるようにして、デバイス上で実行しているアプリのインスタンスを検証し、リクエストが正規の Apple デバイス上の正規のアプリからのものであることを確保します。この機能は改変したアプリがサーバーと通信するのを防ぐのに役立ちます。

このプロセスには、サーバーにより実行される一連の検証とともに、暗号鍵の生成と検証が含まれ、リクエストの真正性を確保します。App Attest はセキュリティを強化しますが、あらゆる形態の不正行為に対する完全な保護を保証するものではないことに注意することが重要です。

詳細については [WWDC 2021](https://developer.apple.com/videos/play/wwdc2021/10244 "WWDC 2021") セッションと ["DeviceCheck ドキュメント"](https://developer.apple.com/documentation/devicecheck/) および ["Validating apps that connect to your server"](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server) を参照してください。
