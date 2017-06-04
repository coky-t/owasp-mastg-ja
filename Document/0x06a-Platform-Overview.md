## iOS プラットフォーム概要

-- [TODO - iOS Platform introduction --]

### iOS セキュリティアーキテクチャ

iOS セキュリティアーキテクチャの主な機能：

- セキュアブート
- サンドボックス
- コード署名
- 暗号化とデータ保護
- 一般的な緩和策

iOS セキュリティアーキテクチャに関する非常に詳細な分析は Johnatan Levin in MacOS and iOS Internals Vol. 3 - http://www.newosxbook.com/2ndUpdate.html <sup>[4]</sup> を参照ください。

#### Hardware Security

The iOS security architecture makes heavy use of hardware-based security features that enhance overall performance and security. Each device comes with two built-in AES 256-bit keys, UID and GID, fused/compiled into the application processor and Secure Enclave during manufacturing. There is no way to directly read these keys through software or debugging interfaces such as JTAG. Encryption and decryption operations are performed by hardware AES crypto-engines with exclusive access to the keys. 

The GID is a common value shared between all processors in a class of devices and known to Apple, and is used to prevent tampering with firmware files and other cryptographic tasks not directly related to the user's private data. UIDs, which are unique to each device, are used to protect the key hierarchy used for device-level file system encrytion. Because they are not recorded during manufacturing, not even Apple can restore the file encryption keys for a particular device.

To enable secure deletion of sensitive data on flash memory, iOS devices inlcude a feature called Effaceable Storage. This feature provides direct low-level access to the storage technology, making it possible to securely erase selected blocks <sup>[6]</sup>.

#### セキュアブート

iOS デバイスの電源を入れると、読み取り専用ブート ROM から初期命令を読み込み、システムをブートストラップします。このメモリには、製造プロセス中にシリコンダイにエッチングされ、信頼されたルートを作成する Apple Root CA とともに、不変コードが含まれています。次にステップでは、ブート ROM コードが iBoot ブートローダーの署名が正しいかどうかをチェックします。署名が検証されると、iBoot は iOS カーネルである次のブートステージの署名をチェックします。これらの手順のいずれかが失敗すると、ブートプロセスは直ちに終了し、デバイスはリカバリモードに入り、"Connect to iTunes" 画面が表示されます。但し、ブート ROM がロードに失敗した場合、デバイスはデバイスファームウェアアップグレード (DFU) と呼ばれる低レベルリカバリモードに入ります。これはデバイスを元の状態に戻すための最後の手段です。これはデバイスの動作の兆候はなく、画面には何も表示されません。

このプロセス全体を「セキュアブートチェーン」と呼び、Apple が製造したデバイス上でのみ実行していることを保証します。セキュアブートチェーンはカーネル、ブートローダー、カーネル拡張、ベースバンドファームウェアで構成されます。
Secure Enclave コプロセッサを搭載したすべての新しいデバイス、つまり iPhone 5s から起動する場合にもセキュアブートプロセスを使用し、Secure Enclave 内のファームウェアが信頼されていることを保証します。

#### サンドボックス

サンドボックスは iOS 向けに提供されたアクセス制御技術であり、カーネルレベルで実施されています。これはアプリが侵害されたときに発生する可能性のあるシステムやユーザーデータへの影響や損害を制限することを目的としています。

iOS サンドボックスはカーネル拡張 'Seatbelt' により実装されている TrustedBSD MAC フレームワークから派生しました。
iPhone Dev Wiki (http://iphonedevwiki.net/index.php/Seatbelt) ではサンドボックスに関する(少し古くなった)情報を提供しています。
原則として、すべてのユーザーアプリケーションは同じユーザー `mobile` の下で実行されますが、ほんの一部のシステムアプリケーションやサービルは `root` として実行されます。ファイル、ネットワークソケット、IPC、共有メモリなどのすべてのリソースへのアクセスはサンドボックスによってコントロールされます。

#### コード署名

アプリケーションコードの署名は Android とは異なります。後者は自己署名鍵で署名でき、主な目的は将来のアプリケーション更新のために信頼されたルートを確立することです。言い換えれば、提供されるアプリケーションのオリジナルの開発者だけがそのアプリケーションを更新できるようにすることです。Android では、アプリケーションを APK ファイルとして、または Google Play から自由に配布できます。
それに対して、Apple は App Store 経由でのみアプリの配布を許可します。

App Store を使用せずにアプリケーションをインストールできるシナリオが少なくとも2つあります。
1. エンタープライズモバイルデバイス管理を経由する。これは企業が Apple により署名された企業の証明書を持っていることが必要となります。
2. サイトローディングを経由する。つまり、開発者の証明書でアプリに署名して開発者のデバイスにインストールします。同じ証明書で使用できるデバイス数には上限があります。

開発者プロファイルと Apple 署名付き証明書はアプリケーションを配布および実行するために必要です。
開発者は、開発や配布に必要なもの一式を得るには、Apple に登録して Apple Developer Program に参加し、サブスクリプション料金 (https://developer.apple.com/support/compare-memberships/) を支払う必要があります。無料アカウントではサイドロードを介してアプリケーションをコンパイルおよび配布できます。

#### 暗号化とデータ保護

Apple は iPhone 3GS のリリース以降 iOS デバイスのハードウェアとファームウェアに暗号化を組み込んでいます。すべてのデバイスには SHA-1 暗号化ハッシュ関数と連携して動作する 256 ビットの AES (Advanced Encryption Standard) に基づいた専用のハードウェアレベルの暗号エンジンが搭載されています。

それに加えて、デバイスのハードウェアに組み込まれた固有識別子 (UID) があり、これはアプリケーションプロセッサに融合した AES 256 ビット鍵です。この UID はデバイス固有であり他には記録されません。執筆時点では、ソフトウェアやファームウェアでは直接読み取ることはできません。鍵がシリコンチップに焼き付けられると、それを改竄やバイパスすることはできません。アクセスできるのは暗号エンジンだけです。これにより最終的にデータは特定のデバイスに暗号的に結び付けられ、したがって他の識別子やデバイスに関連付けることはできません。

物理的なアーキテクチャに暗号化を組み込むことで iOS デバイスに保存されているすべてのデータを簡単に暗号化できます。これにより Apple はデフォルトでこのレベルの暗号化を有効にしており、これを無効にすることはできません。この暗号化の使用はシステムの高速でセキュアなワイプを容易にするための手段としてのみ機能します。これは重要な機能です、特にデバイスを紛失や盗難した際に、リモートワイプが事前に設定されている場合には。このような状況下では、誰かがハックや脱獄をする前に、理論的にはデバイスデータを消去することができます。しかしデバイスを迅速にワイプできない場合、ハッカーはセキュリティを侵害し機密データを取得する可能性があります。

データ保護はソフトウェアレベルで実装され、ハードウェアやファームウェアの暗号化を使用してより高度なセキュリティを提供します。

データ保護が有効な場合、各データファイルは特定のクラスに関連付けられます。異なるレベルのアクセシビリティをサポートし、アクセスが必要なときにクラスに基づいてデータを保護します。各クラスに関連する暗号化および復号化操作は複数の鍵メカニズムに基づいています。デバイスのUID、パスコード、クラス鍵、ファイルシステム鍵、ファイル鍵を使用します。ファイル鍵はファイルの内容を暗号化するために使用されます。クラス鍵はファイル鍵にラップされ、ファイルのメタデータに格納されます。ファイルシステム鍵はメタデータの暗号化に使用されます。UID とパスコードはクラス鍵を保護します。この操作はユーザーには見えず、デバイスがデータ保護を利用するには、デバイスにアクセスする際にパスコードを使用する必要があります。パスコードはデバイスのロックを解除するだけでなく、UID と組み合わせてハッキングやブルートフォース攻撃に強い iOS 暗号化鍵を作成します。このため、ユーザーはデータ保護を有効にするためにデバイスでパスコードを有効にする必要があります。

#### 一般的な緩和策

iOS は現在2つのセキュリティメカニズムを実装しています。アドレス空間配置のランダム化 (ASLR) と eXecute Never (XN) ビットはコード実行攻撃を防止します。

ASLR はプログラムの実行ごとにプログラムの実行可能ファイル、データ、ヒープ、スタックのメモリ位置をランダム化する技術です。共有ライブラリが複数のプロセスにより共有されるためには静的である必要があるため、プログラムが呼び出されるたびにではなく、OS が起動するたびに共有ライブラリのアドレスがランダム化されます。

したがって、これにより関数やライブラリの特定のメモリアドレスを予測することが難しくなり、基本的な libc 関数のメモリアドレスを知ることに依存する、return-to-libc 攻撃などの攻撃を防ぐことができます。

-- TODO [Further develop section on iOS General Exploit Mitigation] --

![iOS Security Architecture (iOS Security Guide)](http://bb-conservation.de/sven/iOS_Security_Architecture.png)
*iOS Security Architecture (iOS Security Guide)*

### iOS でのソフトウェア開発

他のプラットフォームと同様に、Apple は iOS 向けのソフトウェア開発キット (SDK) を提供しています。さまざまなツールやインタフェースを提供することで開発者がネイティブ iOS アプリを開発、インストール、実行、テストできます。この目的のために XCode 統合開発環境 (IDE) が使用され、iOS アプリケーションは Objective-C もしくは Swift を使用して実装されます。

Objective-C は Smalltalk スタイルのメッセージングを C 言語に追加したオブジェクト指向プログラミング言語で、macOS や iOS でそれぞれデスクトップアプリケーションやモバイルアプリケーションを開発するために使用されます。macOS と iOS の両方とも Objective-C を使用して実装されています。

Swift は Objective-C の後継で、相互運用が可能であり、2014年に Xcode 6 で導入されました。

### iOS アプリの理解

iOS アプリケーションは IPA (iOS App Store Package) アーカイブで配布されています。この IPA ファイルにはアプリケーションを実行するために必要な(ARM コンパイルされた)アプリケーションコードとリソースがすべて含まれています。コンテナは ZIP 圧縮ファイルであり、簡単に展開できます。

IPA には iTunes および App Store が認識するための構造が組み込まれています。以下の例は IPA の上位構造を示しています。

* /Payload/ フォルダにはすべてのアプリケーションデータが格納されています。このフォルダの内容を更に詳しく説明します。
* /Payload/Application.app にはアプリケーションデータ自体(ARM コンパイルされたコード)と関連する静的リソースが格納されています
* /iTunesArtwork はアプリケーションのアイコンとして使用される 512x512 ピクセルの PNG 画像です
* /iTunesMetadata.plist には開発者の名前とID、バンドルID、著作権情報、ジャンル、アプリ名、リリース日、購入日など、さまざまな情報が格納されています。
* /WatchKitSupport/WK は extension バンドルの一例です。この固有のバンドルには Apple watch でのインタフェースを管理およびユーザーインタラクションに応答する extension delegate とコントローラが含まれています。

#### IPA ペイロードの内容

ZIP 圧縮された IPA コンテナにあるさまざまなファイルを見てみます。これはバンドルコンテナの未加工のアーキテクチャであり、デバイスにインストールされたあとの最終的な形態ではないことを理解する必要があります。ディスク領域を節約し、ファイルへのアクセスを簡素化するために、余計なディレクトリをほとんど使用しない比較的フラットな構造を使用します。バンドルにはアプリケーション実行可能ファイルとアプリケーションで使用されるリソース(アプリケーションアイコン、その他の画像、ローカライズされたコンテンツなど)が最上位のバンドルディレクトリに格納されます。

* **MyApp**: アプリケーションコードを含む実行可能ファイル。コンパイルされており、「読み取り可能」な形式ではありません。
* **Application**: アプリケーションを表すために特定のときに使用されるアイコン。
* **Info.plist**: バンドルID、バージョン番号、表示名などの構成情報が含まれています。
* **起動画像**: 特定の向きでのアプリケーションの初期インタフェースを示す画像。システムはアプリケーションが完全にロードされるまで、提供された起動画像のひとつを一時的な背景として使用します。
* **MainWindow.nib**: アプリケーション起動時にロードするデフォルトのインタフェースオブジェクトを含みます。他のインタフェースオブジェクトは追加の nib ファイルからロードされるか、アプリケーションによりプログラムで作成されます。
* **Settings.bundle**: プロパティリストや他のリソースファイルを使用して設定や表示するためのアプリケーション固有プリファレンスを含みます。
* **カスタムリソースファイル**: ローカライズされていないリソースは最上位ディレクトリに配置され、ローカライズされたリソースはアプリケーションバンドルの言語固有のサブディレクトリに配置されます。リソースは nib ファイル、画像、音声ファイル、設定ファイル、文字列ファイル、およびアプリケーションに必要なその他のカスタムデータで構成されます。

言語.lproj フォルダはアプリケーションがサポートする言語ごとに定義されています。これにはストーリーボードと文字列ファイルを含んでいます。
* ストーリーボードは iOS アプリケーションのユーザーインタフェースを視覚的に表現したもので、コンテンツの画面と画面間の接続を示します。
* 文字列ファイル形式は1つ以上のキー・バリューのペアとオプションのコメントで構成されます。

![iOS App Folder Structure](http://bb-conservation.de/sven/iOS_project_folder.png)

脱獄済みデバイスでは、IPA インストーラを使用して、インストールされた iOS アプリの IPA を復元できます([テストプロセスと技法](Document/0x05b-Testing-Process-and-Techniques-iOS.md)も参照ください)。注意。モバイルセキュリティアセスメントでは、開発者が IPA を直接提供することがあります。あなたに実際のファイルを送ったり、HockeyApp <sup>[12]</sup> や Testflight <sup>[13]</sup> などの開発用配布プラットフォームへのアクセスを提供することがあります。

#### iOS ファイルシステム上のアプリ構造

iOS 8 以降、アプリケーションがデバイスに格納される方法が変更されました。iOS 8 より前のバージョンでは、アプリケーションは /var/mobile/applications/ にフォルダ内のフォルダにアンパックされます。アプリケーションは UUID (Universal Unique Identifier) 128ビット値によって識別されます。これはアプリケーション自体を見つけるフォルダの名前です。しかし iOS 8 以降これは変更されているので、静的バンドルとアプリケーションデータフォルダはファイルシステムの別の場所に格納されるようになります。これらのフォルダにはアプリケーションセキュリティアセスメント時に綿密に検討する必要がある情報が含まれています。

* /var/mobile/Containers/Bundle/Application/[UUID]/Application.app には前述の application.app データが含まれ、アプリケーションの ARM コンパイル済みバイナリだけでなく静的コンテンツも格納されます。このフォルダのコンテンツはコード署名の検証に使用されます。
* /var/mobile/Containers/Data/Application/[UUID]/Documents にはアプリケーション自体に格納されているすべてのデータが含まれます。このデータの作成はアプリケーションのエンドユーザーによって開始されます。
* /var/mobile/Containers/Data/Application/[UUID]/Library にはアプリケーションに必要なファイルが含まれます。キャッシュ、プリファレンス、クッキー、プロパティリスト (plist) 設定ファイルなど。
* /var/mobile/Containers/Data/Application/[UUID]/Temp にはアプリケーションの起動の間に永続性を必要としない一時ファイルが含まれています。

以下の図はアプリケーションのフォルダ構造を表しています。

![iOS App Folder Structure](http://bb-conservation.de/sven/iOS.png)

#### インストールプロセス

IPA パッケージをデバイスにインストールするにはさまざまな方法があります。最も簡単な方法は Apple のデフォルトのメディアプレーヤーである iTunes を使用することです。iTunes パッケージは OS X および Windows 用が存在します。iTunes を使用すると App Store からアプリをダウンロードしてから iOS デバイスと同期させることができます。App Store は Apple の公式のアプリケーション配布プラットフォームです。また、iTunes を使用してデバイスに ipa をロードすることもできます。Apps セクションに「ドラッグ」して追加すると、デバイスに追加することができます。

Linux では libimobiledevice、クロスプラットフォームのソフトウェアプロトコルライブラリ、iOS デバイスとネイティブに通信するためのツールセットを使用できます。ideviceinstaller を使用すると USB 接続経由でパッケージをインストールできます。接続は USB 多重化デーモン usbmuxd <sup>[8]</sup> を使用して実装され、USB 経由での TCP トンネルを提供します。通常の操作では、iTunes はこの usbmux を使用して iPhone と通信し、ひとつの USB パイプで複数の「接続」を多重化します。ホストマシン上のプロセスはモバイルデバイス上の特定の番号つきポートへの接続をオープンします。<sup>[9]</sup>

iOS デバイスでは、実際のインストールプロセスが installd デーモンによって処理され、アンパックおよびインストールされます。アプリがアプリサービスを統合する(デバイスにインストールされる、もしくは App Store に提出する)前に、Apple が発行した証明書で署名する必要があります。つまりコード署名が有効な場合にのみインストールできます。脱獄済みの電話では Cydia ストアで利用可能なパッケージ AppSync <sup>[10]</sup> を使用して回避することができます。この代替アプリストアには脱獄によって提供されたルート権限を活用する多くの有用なアプリケーションが含まれており、高度な機能を実行します。AppSync は偽の署名付き IPA パッケージのインストールを可能にするために installd にパッチをあてたものです。

IPA は ipainstaller <sup>[11]</sup> を使用してコマンドラインから直接インストールすることもできます。scp (secure copy) を使うなどして、IPA をデバイスにコピーした後、ipainstaller を IPA のファイル名と共に実行することができます。

```bash
$ ipainstaller App_in_scope.ipa
```

#### コード署名と暗号化

Apple は複雑な DRM システムを実装しており、有効で承認されたコードだけが Apple デバイス上で動作するようにしています。つまり、脱獄されていないデバイスでは、Apple が明示的に許可しない限りコードを実行することはできません。Apple 開発者プログラムに登録してプロビジョニングプロファイルと署名証明書を取得しない限り、自分のデバイスでコードを実行することもできません。このような理由から、iOS は crystal prison <sup>[1]</sup> に例えられます。

-- TODO [Develop section on iOS Code Signing and Encryption] --

コード署名に加えて、*FairPlay コード暗号化* が App Store からダウンロードしたアプリに適用されます。もともと、FairPlay は iTunes 経由で購入したマルチメディアコンテンツの DRM の手段として開発されました。その場合、暗号化は MPEG や Quicktime ストリームに適用されましたが、同じ基本概念を実行可能ファイルに適用することもできます。基本的な考え方は次のとおりです。新しい Apple ユーザーアカウントを登録すると、公開鍵/秘密鍵のペアがアカウントに割り当てられます。秘密鍵はデバイスにセキュアに格納されます。つまり FairPlay で暗号化されたコードはあなたのアカウントに関連付けられたデバイスでのみ復号化できます -- TODO [Be more specific] -- 。FairPlay 暗号を復号して取得する一般的な方法は、デバイス上でアプリを実行して、メモリから復号化されたコードをダンプすることです(「セキュリティテスト入門 (iOS)」も参照ください)。

#### アプリサンドボックス

"crystal prison" のテーマに則して、サンドボックスは iOS の最初のリリース以来の中心的なセキュリティ機能です。iOS の通常アプリはアプリ独自のファイルへのアクセスやシステム API のアクセスを制限する「コンテナ」に限定されています。制限事項は <sup>[3]</sup> を参照ください。

- アプリプロセスは chroot 風の仕組みを使用して、自身のディレクトリ(/var/mobile/Containers/Bundle/Application/ 以下)に制限されています。
- mmap と mmprotect() システムコールはアプリが書き込み可能なメモリページを実行可能にしないように変更され、プロセスが動的に生成したコードを実行することを防ぎます。コード署名や FairPlay と組み合わせることで、特定の状況下で実行されるコードが厳しく制限されています(例えば、App Store 経由で配布されるアプリ内のすべてのコードは Apple によって承認されています)。
- 同じ UID によって所有されていても、他の実行中のプロセスから分離します。
- ハードウェアドライバに直接アクセスすることはできません。代わりに、Apple のフレームワークを経由してアクセスします。

### 参考情報

- [1] Apple's Crystal Prison and the Future of Open Platforms - https://www.eff.org/deeplinks/2012/05/apples-crystal-prison-and-future-open-platforms
- [2] Decrypting iOS binaries - https://mandalorian.com/2013/05/03/decrypting-ios-binaries/
- [3] Jonathan Levin, Mac OS X and iOS Internals, Wiley, 2013
- [4] Johnatan Levin, MacOS and iOS Internals, Volume III: Security & Insecurity
- [5] iOS Technology Overview - https://developer.apple.com/library/content/documentation/Miscellaneous/Conceptual/iPhoneOSTechOverview/Introduction/Introduction.html#//apple_ref/doc/uid/TP40007898-CH1-SW1
- [6] iOS Security Guide - https://www.apple.com/business/docs/iOS_Security_Guide.pdf
- [7] How iOS Security Really Works - https://developer.apple.com/videos/play/wwdc2016/705/
- [8] libimobiledevice - http://www.libimobiledevice.org/
- [9] USB Layered Communications - http://wikee.iphwn.org/usb:usbmux
- [10] AppSync - https://cydia.angelxwind.net/?page/net.angelxwind.appsyncunified
- [11] ipainstaller - https://github.com/autopear/ipainstaller
- [12] Hockey Flight - https://hockeyapp.net/
- [13] Testflight - https://developer.apple.com/testflight/
