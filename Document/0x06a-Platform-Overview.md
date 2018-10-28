## iOS プラットフォーム概要

iOS は iPhone, iPad, iPod Touch などの Apple のモバイルデバイスに対応するモバイルオペレーティングシステムです。iOS の多くの機能を継承する Apple tvOS の基礎でもあります。このセクションではアーキテクチャの観点から iOS プラットフォームを紹介します。以下の五つの主要分野について説明します。

1. iOS セキュリティアーキテクチャ
2. iOS アプリケーションの構造
3. プロセス間通信 (IPC)
4. iOS アプリケーションの公開
5. iOS アプリケーション攻撃領域

Apple のデスクトップオペレーティングシステム macOS (以前の OS X) と同様に、Apple により開発されたオープンソースの Unix オペレーティングシステムである Darwin をベースとしています。Darwin のカーネルは XNU ("X is Not Unix") であり、Mach と FreeBSD カーネルのコンポーネントを組み合わせたハイブリッドカーネルです。

しかし、iOS アプリはデスクトップよりも制限された環境で動作します。iOS アプリはファイルシステムレベルで互いに分離されており、システム API アクセスの点で大幅に制限されています。

ユーザーを悪意のあるアプリケーションから保護するために、Apple は iOS デバイス上で実行できるアプリへのアクセスを制限および制御します。Apple App Store は唯一の公式アプリケーション配信プラットフォームです。開発者はアプリを提供でき、消費者はアプリを購入、ダウンロード、インストールできます。この配信スタイルは Android とは異なり、いくつかのアプリストアおよびサイドローディング (公式の App Store を使用せずに iOS デバイスにアプリをインストールする) をサポートしています。

以前は、サイドローディングは脱獄または複雑なワークアラウンドでのみ可能でした。iOS 9 またはそれ以降では、[Xcode 経由でサイドロードする](https://www.igeeksblog.com/how-to-sideload-apps-on-iphone-ipad-in-ios-10/ "How to Sideload Apps on iPhone and iPad Running iOS 10 using Xcode 8") ことが可能です。

iOS アプリは Apple Sandbox (歴史的に Seatbelt と呼ばれている) の、アプリがアクセス可能および不可となるリソースを記述する強制アクセスコントロール (MAC) メカニズムにより互いに分離されています。Android の広範囲の Binder IPC 機能と比較して、iOS は IPC オプションをほとんど提供しないため、潜在的なアタックサーフェイスを最小限に抑えます。

統一されたハードウェアと緊密なハードウェアとソフトウェアの統合はもうひとつのセキュリティのアドバンテージを生み出します。すべての iOS デバイスはセキュアブート、ハードウェア支援のキーチェーン、ファイルシステムの暗号化などのセキュリティ機能を提供します。iOS アップデートは通常すぐにユーザーの大部分に配信され、古く保護されていない iOS バージョンをサポートする必要性が減ります。

iOS には多くの強みがありますが、iOS アプリ開発者はそれでもセキュリティについて心配する必要があります。データ保護、キーチェーン、Touch ID 認証、ネットワークセキュリティは依然としてエラーの余地を多く残しています。以下の章では、iOS セキュリティアーキテクチャについて述べ、基本的なセキュリティテスト手法を説明し、リバースエンジニアリングの方法を提供します。


### iOS セキュリティアーキテクチャ

[iOS セキュリティアーキテクチャ](https://www.apple.com/business/docs/iOS_Security_Guide.pdf "Apple iOS Security Guide") は六つのコア機能で構成されています。

- ハードウェアセキュリティ
- セキュアブート
- コード署名
- サンドボックス
- 暗号化とデータ保護
- 汎用的なエクスプロイト緩和策

![iOS Security Architecture](Images/Chapters/0x06a/iOS_Security_Architecture.png)


#### ハードウェアセキュリティ

iOS セキュリティアーキテクチャは全体的な性能を向上させるハードウェアベースのセキュリティ機能を有効に活用します。各 iOS デバイスには二つの内蔵 Advanced Encryption Standard (AES) 256 ビット鍵 GID と UID が付属しています。製造時にアプリケーションプロセッサおよびセキュアエンクレーブに融合されコンパイルされます。ソフトウェアや JTAG などのデバッグインタフェースでこれらの鍵を読む直接的な方法はありません。暗号化および復号化操作は、これらの鍵への排他的アクセスを行うハードウェア AES 暗号エンジンにより実行されます。

GID はデバイスクラス内のすべてのプロセッサで共有される値であり、ユーザーの個人データに直接関係しないファームウェアファイルやその他の暗号化タスクの改竄を防止するために使用されます。各デバイスに固有の UID はデバイスレベルのファイルシステムの暗号化に使用される鍵階層を保護するために使用されます。UID は製造中に記録されないため、Apple でも特定のデバイスのファイル暗号鍵を復元することはできません。

フラッシュメモリの機密データを安全に削除するために、iOS デバイスには [Effaceable Storage](https://www.apple.com/business/docs/iOS_Security_Guide.pdf "iOS Security Guide") という機能があります。この機能はストレージテクノロジへの直接的な低レベルアクセスを提供し、選択されたブロックを安全に消去することを可能にします。

#### セキュアブート

iOS デバイスの電源を入れると、読み取り専用ブート ROM から初期命令を読み込み、システムをブートストラップします。ブート ROM には不変コードと Apple Root CA が含まれています。製造プロセス中にシリコンダイにエッチングされ、それにより信頼されたルートを作成します。次に、ブート ROM コードは iBoot ブートローダーの署名が正しいことを確認します。署名が検証された後、iBoot は iOS カーネルである次のブートステージの署名をチェックします。これらの手順のいずれかが失敗すると、ブートプロセスは直ちに終了し、デバイスはリカバリモードに入り、"Connect to iTunes" 画面を表示します。但し、ブート ROM がロードに失敗した場合、デバイスはデバイスファームウェアアップグレード (DFU) と呼ばれる低レベルリカバリモードに入ります。これはデバイスを元の状態に復元するための最後の手段です。このモードでは、デバイスは動作の兆候を示しません。つまり、画面には何も表示されません。

このプロセス全体を「セキュアブートチェーン」と呼びます。その目的は、システムとそのコンポーネントが Apple により作成及び配布されることを保証することです。セキュアブートチェーンはカーネル、ブートローダー、カーネル拡張、ベースバンドファームウェアで構成されます。

#### コード署名

Apple は Apple が承認したコードだけがデバイス上で動作するように精巧な DRM システムを実装しています。言い換えれば、Apple が明示的に許可しない限り、脱獄されていない iOS デバイス上で任意のコードを実行することはできません。エンドユーザーは公式の Apple App Store を通じてのみアプリをインストールするようになっています。この理由 (およびその他) のために、iOS は [crystal prison とみなされています](https://www.eff.org/deeplinks/2012/05/apples-crystal-prison-and-future-open-platforms "Apple's Crystal Prison and the Future of Open Platforms") 。

アプリケーションを配布および実行するには開発者プロファイルと Apple 署名証明書が必要です。
開発者は Apple に登録する必要があります。[Apple Developer Program](https://developer.apple.com/support/compare-memberships/ "Membership for Apple Developer Program") に参加し、年間サブスクリプションを支払うことで開発と配布の可能性を広げます。また、サイドローディングを介してアプリをコンパイルおよび配布することもできます (但し、App Store には配布しません) 。

#### 暗号化とデータ保護

*FairPlay コード暗号化* は App Store からダウンロードしたアプリに適用されます。FairPlay は iTunes で購入したマルチメディアコンテンツの DRM として開発されました。もともと、FairPlay の暗号化は MPEG や QuickTime ストリームに適用されていましたが、同じ基本概念を実行可能ファイルにも適用できます。基本的な考え方は次の通りです。新しい Apple ユーザーアカウントを登録すると、公開鍵と秘密鍵 (private key) のペアが作成され、アカウントに割り当てられます。その秘密鍵 (private key) はデバイス上にセキュアに格納されます。つまり FairPlay で暗号化されたコードはアカウントに関連付けられたデバイス上でのみ復号できます。FairPlay 暗号のリバースは通常、デバイス上でアプリを実行し、メモリから復号されたコードをダンプして取得します (「iOS アプリのテスト環境構築」も参照してください) 。

Apple は iPhone 3GS のリリース以降 iOS デバイスのハードウェアとファームウェアに暗号化を組み込んでいます。すべてのデバイスには SHA-1 暗号化ハッシュ関数と連携して動作する 256 ビット AES に基づいた専用のハードウェアレベルの暗号エンジンが搭載されています。それに加えて、これはアプリケーションプロセッサに融合した AES 256 ビット鍵とともに、各デバイスのハードウェアに組み込まれた固有識別子 (UID) があります。この UID は一意であり他には記録されません。執筆時点では、ソフトウェアやファームウェアでは直接読み取ることはできません。鍵はシリコンチップに焼き付けられるため、それを改竄やバイパスすることはできません。暗号エンジンだけがアクセスできます。

物理的なアーキテクチャに暗号化を組み込むことで iOS デバイスに保存されているすべてのデータを暗号化できるデフォルトのセキュリティ機能を実現します。その結果、データ保護はソフトウェアレベルで実装され、ハードウェアとファームウェアの暗号化を使用してセキュリティを強化します。

データ保護が有効な場合、各データファイルは特定のクラスに関連付けられます。それぞれのクラスは異なるレベルのアクセシビリティをサポートし、データにアクセスが必要なときに基づいてデータを保護します。各クラスに関連する暗号化および復号化操作は複数の鍵メカニズムに基づいています。デバイスのUID、パスコード、クラス鍵、ファイルシステム鍵、ファイルごとの鍵を使用します。ファイルごとの鍵はファイルの内容を暗号化するために使用されます。クラス鍵はファイルごとの鍵にラップされ、ファイルのメタデータに格納されます。ファイルシステム鍵はメタデータの暗号化に使用されます。UID とパスコードはクラス鍵を保護します。この操作はユーザーには見えません。データ保護を有効にするには、デバイスにアクセスする際にパスコードを使用する必要があります。パスコードはデバイスのロックを解除します。UID と組み合わせることにより、パスコードはハッキングやブルートフォース攻撃により耐性のある iOS 暗号化鍵を作成します。ユーザーがデバイスでパスコードを使用する主な理由はデータ保護を有効にするためです。

#### サンドボックス

[アプリサンドボックス](https://developer.apple.com/library/content/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html "File System Basics") は iOS アクセス制御技術です。それはカーネルレベルで実施されています。これはアプリが侵害されたときに発生する可能性のあるシステムやユーザーデータへの損害を制限することを目的としています。

サンドボックスは iOS の最初のリリースから主要なセキュリティ機能です。すべてのサードパーティアプリは同じユーザー `mobile` の下で実行されますが、ほんの一部のシステムアプリケーションやサービルは `root` として実行されます。ファイル、ネットワークソケット、IPC、共有メモリなどのすべてのリソースへのアクセスはサンドボックスによってコントロールされます。通常の iOS アプリは *コンテナ* に限定されています。アプリ自身のファイルへのアクセスと非常に限られた数のシステム API に制限されています。すべてのリソース (ファイル、ネットワークソケット、IPC、共有メモリなど) へのアクセスはサンドボックスにより制御されています。これらの制限は以下のように機能します。 [#levin]

- アプリプロセスは chroot のようなプロセスを介して自身のディレクトリ (/var/mobile/Containers/Bundle/Application/ の下) に制限されています。
- `mmap` および `mmprotect` システムコールは修正されています。アプリが書き込み可能なメモリページを実行可能にすることを防ぎ、動的に生成されたコードを実行するプロセスを停止します。コード署名と FairPlay を組み合わせることで、特定の条件下で実行できるコードを厳しく制限します (例えば、App Store を介して配布されるアプリ内のすべてのコードは Apple により承認されています) 。
- プロセスは同じ UID により所有されているとしても、互いに分離されています。
- ハードウェアドライバに直接的にアクセスすることはできません。代わりに、Apple のフレームワークを通じてアクセスする必要があります。

#### 汎用的なエクスプロイト緩和策

iOS はアドレス空間配置のランダム化 (ASLR) と eXecute Never (XN) ビットを実装してコード実行攻撃を軽減しています。

ASLR は、プログラムが実行されるごとに、プログラムの実行可能ファイル、データ、ヒープ、スタックのメモリ位置をランダム化します。共有ライブラリは複数のプロセスがアクセスするために静的である必要があるため、プログラムが呼び出されるごとではなく、OS がブートするごとに共有ライブラリのアドレスはランダム化されます。これにより、特定の関数やライブラリのメモリアドレスを予測することが難しくなり、基本的な libc 関数のメモリアドレスに関わる return-to-libc 攻撃などの攻撃を防ぎます。

XN メカニズムにより iOS はプロセスの選択されたメモリセグメントを実行不可とマークできます。iOS では、ユーザーモードプロセスのプロセススタックとヒープには実行不可とマークされます。書き込み可能であるページには同時に実行可能とマークすることはできません。これにより攻撃者がスタックやヒープに注入したマシンコードを実行することを防ぎます。

### iOS でのソフトウェア開発

他のプラットフォームと同様に、Apple は iOS 向けのソフトウェア開発キット (SDK) を提供しています。開発者がネイティブ iOS アプリを開発、インストール、実行、テストするのに役立ちます。Xcode は Apple が開発した統合開発環境 (IDE) です。iOS アプリケーションは Objective-C もしくは Swift で開発されます。

Objective-C は Smalltalk スタイルのメッセージングを C 言語に追加したオブジェクト指向プログラミング言語で、macOS でのデスクトップアプリケーションを開発するために、また iOS でのモバイルアプリケーションを開発するために使用されます。Swift は Objective-C の後継であり、Objective-C との相互運用が可能です。

Swift は2014年に Xcode 6 で導入されました。

非脱獄デバイスでは、App Store なしでアプリケーションをインストールするには二つの方法があります。

1. エンタープライズモバイルデバイス管理を介します。これには Apple が署名した会社レベルの証明書が必要です。
2. サイドローディングを介します。すなわち、開発者の証明書でアプリに署名し、Xcode 経由でデバイスにインストールします。限られた数のデバイスに同じ証明書でインストールできます。

### iOS でのアプリ

iOS アプリは IPA (iOS App Store Package) アーカイブで配布されています。この IPA ファイルは ZIP 圧縮されたアーカイブであり、アプリを実行するために必要なコードとリソースをすべて含んでいます。

IPA ファイルにはビルトインのディレクトリ構造を持っています。以下の例はこの構造を上位レベルで示しています。

- `/Payload/` フォルダにはすべてのアプリケーションデータが格納されています。このフォルダの内容を更に詳しく説明します。
- `/Payload/Application.app` にはアプリケーションデータ自体 (ARM コンパイルされたコード) と関連する静的リソースが格納されています。
- `/iTunesArtwork` はアプリケーションのアイコンとして使用される 512x512 ピクセルの PNG 画像です。
- `/iTunesMetadata.plist` には開発者の名前とID、バンドルID、著作権情報、ジャンル、アプリ名、リリース日、購入日など、さまざまな情報が格納されています。
- `/WatchKitSupport/WK` は extension バンドルの一例です。この固有のバンドルには Apple watch でのインタフェースを管理およびユーザーインタラクションに応答する extension delegate とコントローラが含まれています。

#### IPA ペイロードの詳細

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

![iOS App Folder Structure](Images/Chapters/0x06a/iOS_project_folder.png)

脱獄済みデバイスでは、[IPA Installer](https://github.com/autopear/ipainstaller "IPA Installer") を使用して、インストールされた iOS アプリの IPA を復元できます。モバイルセキュリティアセスメントでは、開発者が IPA を直接提供することがよくあります。あなたに実際のファイルを送ったり、[HockeyApp](https://hockeyapp.net/ "HockeyApp") や [Testflight](https://developer.apple.com/testflight/ "Testflight") などの開発用配布プラットフォームへのアクセスを提供することがあります。

#### iOS ファイルシステム上のアプリ構造

iOS 8 以降、アプリケーションがデバイスに格納される方法が変更されました。それ以前では、アプリケーションは /var/mobile/applications/ にフォルダ内のフォルダにアンパックされました。iOS 10 以降、パスは `/private/var/containers/Bundle/Application/` に変更されていることに注意します。アプリケーションは UUID (Universal Unique Identifier) 128ビット値によって識別されました。この番号はアプリケーション自体を格納するフォルダの名前でした。静的バンドルとアプリケーションデータフォルダは現在では別の場所に格納されています。これらのフォルダにはアプリケーションセキュリティアセスメント時に綿密に検討する必要がある情報が含まれています。

- `/var/mobile/Containers/Bundle/Application/[UUID]/Application.app` には前述の application.app データが含まれ、アプリケーションの ARM コンパイル済みバイナリだけでなく静的コンテンツも格納されます。このフォルダのコンテンツはコード署名の検証に使用されます。
- `/var/mobile/Containers/Data/Application/[UUID]/Documents` にはユーザーが生成したすべてのデータが含まれます。アプリケーションエンドユーザーがこのデータの作成を開始します。
- `/var/mobile/Containers/Data/Application/[UUID]/Library` にはユーザー固有ではないすべてのファイルが含まれます。キャッシュ、プリファレンス、クッキー、プロパティリスト (plist) 設定ファイルなどがあります。
- `/var/mobile/Containers/Data/Application/[UUID]/tmp` にはアプリケーションの機能の間に必要とされない一時ファイルが含まれます。

以下の図はアプリケーションのフォルダ構造を表しています。
![iOS App Folder Structure](Images/Chapters/0x06a/iOS_Folder_Structure.png)

#### インストールプロセス

IPA パッケージを iOS デバイスにインストールするにはさまざまな方法があります。最も簡単な方法は [Cydia Impactor](http://www.cydiaimpactor.com/ "Cydia Impactor") を使うことです。このツールはもともと iPhone を脱獄するために作成されたものですが、IPA パッケージに署名して iOS デバイスにインストールするように書き直されました。このツールは MacOS, Windows, Linux で利用でき、APK ファイルを Android デバイスにインストールすることもできます。 [ステップバイステップガイドとトラブルシューティングの手順はこちらにあります](https://yalujailbreak.net/how-to-use-cydia-impactor/ "How to use Cydia Impactor") 。


Linux では、代わりにクロスプラットフォームのソフトウェアプロトコルライブラリである [libimobiledevice](http://www.libimobiledevice.org/ "libimobiledevice") と、iOS デバイスとネイティブに通信するためのツールセットを使用できます。ideviceinstaller を介して USB 接続経由でパッケージをインストールできます。接続は USB 多重化デーモン [usbmuxd](https://www.theiphonewiki.com/wiki/Usbmux "Usbmux") を使用して実装され、USB 経由での TCP トンネルを提供します。

iOS デバイスでは、実際のインストールプロセスは installd デーモンにより処理され、アプリケーションをアンパックおよびインストールします。アプリサービスを統合する、もしくは iOS デバイスにインストールされるには、すべてのアプリケーションは Apple が発行した証明書で署名されている必要があります。これはコード署名の検証が成功した後にのみアプリケーションがインストールされることを意味します。但し、脱獄済みの電話機では、Cydia ストアで利用できる [AppSync](http://repo.hackyouriphone.org/appsyncunified) でこのセキュリティ機能を回避できます。Cydia は代替アプリストアです。この代替アプリストアには脱獄によって提供されたルート権限を活用して高度な機能を実行する多くの有用なアプリケーションが含まれています。AppSync は偽の署名付き IPA パッケージのインストールを可能にするために installd にパッチをあてたものです。

IPA は [ipainstaller](https://github.com/autopear/ipainstaller "IPA Installer") を使用してコマンドラインから直接インストールすることもできます。例えば scp 経由などで、ファイルをデバイスにコピーした後、ipainstaller を IPA のファイル名と共に実行します。

```shell
$ ipainstaller App_name.ipa
```

#### アプリパーミッション

Android アプリとは異なり、iOS アプリは事前に割り当てられたパーミッションを持ちません。代わりに、アプリが初めてセンシティブな API を使用しようとした際に、実行時にパーミッションを与えるようユーザーに求めます。パーミッションを付与されたアプリは 設定 > プライバシー メニューに表示され、ユーザーはアプリ固有の設定を変更できます。Apple はこのパーミッションコンセプト [プライバシー管理](https://support.apple.com/en-sg/HT203033 "Apple - About privacy and Location Services in iOS 8 and later") を呼び出します。

iOS 開発者はパーミッションを直接設定することはできません。間接的にセンシティブな API で要求します。例えば、ユーザーの連絡先にアクセスすると、ユーザーがアクセスを許可または拒否するよう求められている間、CNContactStore へのコールはアプリをブロックします。iOS 10.0 以降、アプリはアクセスする必要があるデータのタイプについて usage description キーを含む必要があります (NSContactsUsageDescription など)。

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

### iOS アプリケーション攻撃領域

iOS アプリケーション攻撃領域はそのアプリケーションのすべてのコンポーネントで構成されます。アプリをリリースおよびその機能をサポートするために必要なサポートマテリアルを含みます。iOS アプリケーションは以下を行っていない場合、攻撃に対して脆弱である可能性があります。
- IPC 通信や URL スキームによるすべての入力を検証します。以下を参照してください。
  - [カスタム URL スキームのテスト](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x06h-Testing-Platform-Interaction.md#testing-custom-url-schemes "Testing Custom URL Schemes")
- ユーザーによる入力フィールドへのすべての入力を検証します。
- WebView 内にロードされるコンテンツを検証します。以下を参照してください。
  -  [iOS WebView のテスト](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x06h-Testing-Platform-Interaction.md#testing-ios-webviews "Testing iOS webviews")
  - [ネイティブメソッドが WebView を通じて公開されているかどうかを判断する](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x06h-Testing-Platform-Interaction.md#determining-whether-native-methods-are-exposed-through-webviews "Determining Whether Native Methods Are Exposed Through WebViews")
- バックエンドサーバーとセキュアに通信しています。そうでなければサーバーとモバイルアプリケーションの間で中間者攻撃の影響を受けます。以下を参照してください。
  - [ネットワーク通信のテスト](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x04f-Testing-Network-Communication.md#testing-network-communication "Testing Network Communication")
  - [iOS ネットワーク API](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x06g-Testing-Network-Communication.md#ios-network-apis "iOS Network APIs")
- すべてのローカルデータをセキュアに保存しています。そうでなければストレージから信頼できないデータをロードします。以下を参照してください。
  - [iOS のデータストレージ](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x06d-Testing-Data-Storage.md#data-storage-on-ios "Data Storage on iOS")
- 危殆化した環境、再パッケージ化あるいはその他のローカル攻撃から自身を保護しています。以下を参照してください。
  - [iOS アンチリバース防御](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x06j-Testing-Resiliency-Against-Reverse-Engineering.md#ios-anti-reversing-defenses "iOS Anti-Reversing Defenses")
