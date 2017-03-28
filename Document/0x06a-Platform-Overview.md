## iOS プラットフォーム概要

他のプラットフォームと同様に、Apple は iOS 向けのソフトウェア開発キット (SDK) を提供しています。さまざまなツールやインタフェースを提供することで開発者がネイティブ iOS アプリを開発、インストール、実行、テストできます。この目的のために XCode 統合開発環境 (IDE) が使用され、iOS アプリケーションは Objective-C もしくは Swift を使用して実装されます。

Objective-C は Smalltalk スタイルのメッセージングを C 言語に追加したオブジェクト指向プログラミング言語で、macOS や iOS でそれぞれデスクトップアプリケーションやモバイルアプリケーションを開発するために使用されます。macOS と iOS の両方とも Objective-C を使用して実装されています。

Swift は Objective-C の後継で、相互運用が可能であり、2014年に XCode 6 で導入されました。

### iOS セキュリティアーキテクチャ

iOS セキュリティアーキテクチャの主な機能：

- セキュアブート
- サンドボックス
- コード署名
- 暗号化とデータ保護
- 一般的な緩和策

#### セキュアブート

iOS デバイスの電源を入れると、読み取り専用ブート ROM から初期命令を読み込み、システムをブートストラップします。この起動プロセスの中で、「セキュアブートチェーン」は検証済み Apple デバイス上で実行していることを保証します。このプロセスは次のステップがセキュアであり検証が成功した場合にのみ進められます。セキュアブートチェーンはカーネル、ブートローダー、カーネル拡張、ベースバンドファームウェアで構成されます。

-- TODO [Further develop section on iOS Secure Boot] --

#### サンドボックス

サンドボックスは iOS 向けに提供されたアクセス制御技術であり、カーネルレベルで実施されています。これはアプリが侵害されたときに発生する可能性のあるシステムやユーザーデータへの影響や損害を制限することを目的としています。iOS AppStore 経由で配布されるすべてのアプリはこの目的のためにサンドボックスを採用する必要があります。

-- TODO [Further develop section on iOS Sandbox] --

#### コード署名

iOS アプリケーションをインストールする前に、その起源を認証する必要があります。iOS アプリが不特定のウェブサイトからダウンロードされた場合、マルウェアとして分類される可能性のある重大なリスクがあります。リスクを大幅に軽減でき、ソフトウェアの起源を検証できる場合には、転送中に改変されていないことをさらに保証することもできます。

したがって、コード署名はこの保証を提供するためのメカニズムを提供します。X.509v3 証明書を使用することにより、発行者の秘密鍵で公開鍵に署名する開発者の場合では、開発者はアプリケーションに署名することで自分の身元を証明することができます。

-- TODO [Further develop section on iOS Code Signing] --

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

脱獄済みデバイスでは、IPA インストーラを使用して、インストールされた iOS アプリの IPA を復元できます([テストプロセスと技法](Document/0x05b-Testing-Process-and-Techniques-iOS.md)も参照ください)。注意。モバイルセキュリティアセスメントでは、開発者が IPA を直接提供することがあります。あなたに実際のファイルを送ったり、[HockeyApp] や [Testflight] などの開発用配布プラットフォームへのアクセスを提供することがあります。

#### iOS ファイルシステム上のアプリ構造

Since iOS 8, changes were made to the way an application is stored on the device. On versions before iOS 8, applications would be unpacked to a folder in the /var/mobile/applications/ folder. The application would be identified by its UUID (Universal Unique Identifier), a 128-bit number. This would be the name of the folder in which we will find the application itself. Since iOS 8 this has changed however, so we will see that the static bundle and the application data folders are now stored in different locations on the filesystem. These folders contain information that we will need to closely examine during application security assessments.

* /var/mobile/Containers/Bundle/Application/[UUID]/Application.app contains the previously mentioned application.app data and stores the static content as well as the ARM compiled binary of the application. The content of this folder will be used to validate the code signature.
* /var/mobile/Containers/Data/Application/[UUID]/Documents contains all the data stored for the application itself. The creation of this data is initiated by the application’s end user.
* /var/mobile/Containers/Data/Application/[UUID]/Library contains files necessary for the application e.g. caches, preferences, cookies, property list (plist) configuration files, etc.
* /var/mobile/Containers/Data/Application/[UUID]/Temp contains temporary files which do not need persistence in between application launches.

The following figure represents the application’s folder structure:

![iOS App Folder Structure](http://bb-conservation.de/sven/iOS.png)

#### インストールプロセス

Different methods exist to install an IPA package on the device. The easiest solution is to use iTunes, which is the default media player from Apple. ITunes Packages exist for OS X as well as for Windows. iTunes allows you to download applications through the App Store, after which you can synchronise them to an iOS device. The App store is the official application distribution platform from Apple. You can also use iTunes to load an ipa to a device. This can be done by adding “dragging” it into the Apps section, after which we can then add it to a device.

On Linux we can make use of libimobiledevice, a cross-platform software protocol library and set of tools to communicate with iOS devices natively. Through ideviceinstaller we can install packages over an USB connection. The connection is implemented using USB multiplexing daemon [usbmuxd] which provides a TCP tunnel over USB. During normal operations, iTunes communicates with the iPhone using this usbmux, multiplexing several “connections” over the one USB pipe. Processes on the host machine open up connections to specific, numbered ports on the mobile device. [usbmux]

On the iOS device, the actual installation process is then handled by installd daemon, which will unpack and install it. Before your app can integrate app services, be installed on a device, or be submitted to the App Store, it must be signed with a certificate issued by Apple. This means that we can only install it after the code signature is valid. On a jailbroken phone this can however be circumvented using [AppSync], a package made available on the Cydia store. This is an alternate app store containing a lot of useful applications which leverage root privileges provided through the jailbreak in order to execute advanced functionalities. AppSync is a tweak that patches installd to allow for the installation of fake-signed IPA packages.

The IPA can also be installed directly from command line by using [ipainstaller]. After copying the IPA onto the device, for example by using scp (secure copy), the ipainstaller can be executed with the filename of the IPA:

```bash
$ ipainstaller App_in_scope.ipa
```

#### コード署名と暗号化

Apple has implemented an intricate DRM system to make sure that only valid & approved code runs on Apple devices. In other words, on a non-jailbroken device, you won't be able to run any code unless Apple explicitly allows you to. You can't even opt to run code on your own device unless you enroll with the Apple developer program and obtain a provisioning profile and signing certificate. For this and other reasons, iOS has been compared to a crystal prison [1].

-- TODO [Develop section on iOS Code Signing and Encryption] --

In addition to code signing, *FairPlay Code Encryption* is applied to apps downloaded from the App Store. Originally, FairPlay was developed as a means of DRM for multimedia content purchased via iTunes. In that case, encryption was applied to MPEG and Quicktime streams, but the same basic concepts can also be applied to executable files. The basic idea is as follows: Once you register a new Apple user account, a public/private key pair is created and assigned to your account. The private key is stored securely on your device. This means that Fairplay-encrypted code can be decrypted only on devices associated with your account -- TODO [Be more specific] --. The usual way to obtain reverse FairPlay encryption is to run the app on the device and then dump the decrypted code from memory (see also "Basic Security Testing on iOS").

#### アプリサンドボックス

In line with the "crystal prison" theme, sandboxing has been is a core security feature since the first releasees of iOS. Regular apps on iOS are confined to a "container" that restrict access to the app's own files and a very limited amount of system APIs. Restrictions include [3]:

- The app process is restricted to it's own directory(below /var/mobile/Containers/Bundle/Application/) using a chroot-like mechanism.
- The mmap and mmprotect() system calls are modified to prevent apps from make writeable memory pages executable, preventing processes  from executing dynamically generated code. In combination with code signing and FairPlay, this places strict limitations on what code can be run under specific circumstances (e.g., all code in apps distributed via the app store is approved by Apple).
- Isolation from other running processes, even if they are owned by the same UID;
- Hardware drivers cannot be accessed directly. Instead, any access goes through Apple's frameworks.

### 参考情報

- [1] Apple's Crystal Prison and the Future of Open Platforms - https://www.eff.org/deeplinks/2012/05/apples-crystal-prison-and-future-open-platforms
- [2] Decrypting iOS binaries - https://mandalorian.com/2013/05/03/decrypting-ios-binaries/
- [3] Jonathan Levin, Mac OS X and iOS Internals, Wiley, 2013

+ [iOS Technology Overview](https://developer.apple.com/library/content/documentation/Miscellaneous/Conceptual/iPhoneOSTechOverview/Introduction/Introduction.html#//apple_ref/doc/uid/TP40007898-CH1-SW1)
+ [iOS Security Guide](https://www.apple.com/business/docs/iOS_Security_Guide.pdf)
+ [How iOS Security Really Works](https://developer.apple.com/videos/play/wwdc2016/705/)
- [usbmuxd](http://www.libimobiledevice.org/)
- [usbmux](http://wikee.iphwn.org/usb:usbmux)
- [AppSync](https://cydia.angelxwind.net/?page/net.angelxwind.appsyncunified)
- [ipainstaller](https://github.com/autopear/ipainstaller)
- [Hockey Flight](https://hockeyapp.net/)
- [Testflight](https://developer.apple.com/testflight/)
