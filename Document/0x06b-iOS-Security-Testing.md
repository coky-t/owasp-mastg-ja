## セキュリティテスト入門 (iOS)

### Swift および Objective-C の紹介

このチュートリアルのほとんどは主に Objective-C で書かれたアプリケーションやブリッジされた Swift タイプのアプリケーションに関連しています。これらの言語は基本的に異なることに注意してください。Cycript で頻繁に使用されるメソッドスウィズルなどの機能は Swift メソッドでは機能しません。このテストガイドの執筆時には、Frida は Swift メソッドの計装をサポートしていません。

### テスト環境のセットアップ

**iOS テストラボの要件**

最小構成

- 管理者権限を持つラップトップ、Kali Linux を搭載した VirtualBox
- クライアントからクライアントへのトラフィックが許可された WiFi ネットワーク (USB を介した多重化も可能)
- Hopper 逆アセンブラ
- 少なくとも一つの脱獄済み iOS デバイス (必要な iOS バージョンのもの)
- Burp Suite ツール

推奨構成
- Xcode と開発者プロファイルありの MacBook
- 前述と同様の WiFi ネットワーク
- Hopper 逆アセンブラもしくは Hex Rays の IDA Pro
- 少なくとも二つの iOS デバイス、一つは脱獄済み、二つ目は脱獄なし
- Burp Suite ツール

### iOS の脱獄

iOS の世界では、脱獄は Apple のコード署名メカニズムを無効にして、Apple が署名していないアプリを実行できるにすることを意味します。iOS デバイスで何かしらの動的セキュリティテストを行う予定がある場合、最も有用なテストツールはアプリストア以外でのみ利用可能であるため、脱獄済みデバイスで作業がはるかに楽になります。

エクスプロイトチェーンと脱獄の間には重要な違いがあります。前者はコード署名や MAC などの iOS システム保護を無効にしますが、Cydia ストアはインストールしません。脱獄はエクスプロイトチェーンを活用し、システム保護を無効にして、Cydia をインストールする完全なツールです。

脱獄用語で、紐付きと紐なし脱獄手法についてお話しします。「紐付き」シナリオでは、脱獄は再起動前後で持続しないため、再起動するたびにデバイスをコンピュータに接続 (紐付き) して再適用する必要があります。「紐なし」脱獄は一度しか適用する必要がなく、エンドユーザーにとって最も人気のある選択となっています。

脱獄手法は iOS のバージョンによって異なります。最良の選択はあなたの iOS バージョンに対して一般的な脱獄が利用可能であるかどうかを確認することです <sup>[25]</sup> 。脱獄グループや著者に似たドメイン名で隠した、インターネットでしばしば配布されている偽ツールやスパイウェアに注意します。

**重要** iOS の脱獄に関する注意：Android とは異なり、あなたは下記の例外を除いて iOS バージョンをダウングレード **できません** 。当然ながら、iOS バージョンに大きなバンプがあり (9 から 10 など)、新しい OS に公開された脱獄が存在しないとき、これは問題を引き起こします。一つの可能な解決策は少なくとも二つの iOS デバイスを持つことです。一つは脱獄済みでテストに必要なすべてのツールを持ち、二つ目はすべての主要な iOS リリースごとに更新され、公開された脱獄がリリースされるまで待ちます。一旦公開された脱獄がリリースされると、Apple はパッチをリリースするのがかなり速いので、数日中に最新の iOS バージョンにアップグレードして脱獄する必要があります (アップグレードが必要な場合) 。
iOS のアップグレードプロセスはオンラインで実行され、チャレンジレスポンスプロセスに基づいています。チャレンジに対するレスポンスが Apple により署名されている場合にのみ、デバイスは OS インストールを実行します。これは研究者が「署名ウィンドウ」と呼ぶものです。iTunes 経由でダウンロードした OTA ファームウェアパッケージを保存していつでもデバイスにロードすることはできないという事実を説明しています。iOS のマイナーアップグレードでは、Apple により同時に二つのバージョンが署名されている可能性があります。これはiOS バージョンをダウングレードできる可能性のある唯一のケースです。このサイト <sup>[30]</sup> から現在の署名ウィンドウを確認し、OTA ファームウェアをダウンロードできます。脱獄の詳細については iPhone Wiki <sup>[26]</sup> を参照ください。

### テスト環境の準備

![Cydia Store](Images/Chapters/0x06b/cydia.png "Cydia Store")

iOS デバイスを脱獄させて Cydia が (スクリーンショットと同様に) インストールされたら、以下の手順に従います。

1. Cydia から aptitude と openssh をインストールする
2. iDevice へ SSH する
  * 二つのユーザー `root` と `mobile` がある
  * デフォルトパスワードは `alpine` である
3. Cydia に次のリポジトリを追加する `https://build.frida.re`
4. Cydia から Frida をインストールする
5. aptitude で以下のパッケージをインストールする

```
inetutils 
syslogd 
less 
com.autopear.installipa 
class-dump 
com.ericasadun.utilities 
odcctools
cycript 
sqlite3 
adv-cmds 
bigbosshackertools
```

あなたのワークステーションには SSH クライアント、Hopper 逆アセンブラ、Burp、Frida がインストールされている必要があります。pip で Frida をインストールできます。

```
$ sudo pip install frida
```

#### USB 経由の SSH 接続

通常の動作と同様に、iTunes は <code>usbmux</code> を経由して iPhone と通信します。<code>usbmux</code> は一つの USB パイプで複数の「接続」を多重化するシステムです。このシステムは TCP のようなシステムを提供します。ホストマシン上の複数のプロセスがモバイルデバイス上の特定の番号付きポートへの接続を開きます。

*usbmux* は */System/Library/PrivateFrameworks/MobileDevice.framework/Resources/usbmuxd* により処理されます。USB を経由して iPhone 接続を監視するソケットデーモンです <sup>[18]</sup> 。これを使用して、モバイルデバイスのローカルホストソケットをホストマシンの TCP ポートに接続することができます。これによりネットワーク設定とは関係なくデバイスに SSH を使用できます。標準モードで動作している iPhone を検出すると、iPhone に接続して、*/var/run/usbmuxd* <sup>[27]</sup> 経由で受信したリクエストの中継を開始します。

MacOS

```
$ brew install libimobiledevice
$ iproxy 2222 22
$ ssh -p 2222 root@localhost
iPhone:~ root# 
```

Python クライアント

```bash
$ ./tcprelay.py -t 22:2222
$ ssh -p 2222 root@localhost
iPhone:~ root# 
```
iphonedevwiki <sup>[24]</sup> も参照ください。

### 一般的な iOS アプリケーションテストのワークフロー

iOS アプリケーションテストの一般的なワークフローは以下のとおりです。

1. IPA ファイルを入手する
2. 脱獄検出をバイパスする (存在する場合)
3. 証明書ピンニングをバイパスする (存在する場合)
4. HTTP(S) トラフィックを検査する - 通常の Web アプリテスト
5. ランタイム操作によりアプリケーションロジックを不正使用する
6. ローカルデータストレージ (キャッシュ、バイナリクッキー、plist、データベース) を確認する
7. クライアント固有のバグ SQLi や XSS などを確認する
8. その他の確認：NSLog を使用した ASL へのログ出力、アプリケーションのコンパイルオプション、アプリケーションのスクリーンショット、アプリのバックグラウンド化有無

### 静的解析

#### ソースコードあり

-- TODO [Add content on security Static Analysis of an iOS app with source code] --

#### ソースコードなし

##### フォルダ構造

システムアプリケーションは `/Applications` にあります。
残りについてはすべて、`installipa` を使用して適切なフォルダにナビゲートできます [14]

```
iOS8-jailbreak:~ root# installipa -l
me.scan.qrcodereader
iOS8-jailbreak:~ root# installipa -i me.scan.qrcodereader
Bundle: /private/var/mobile/Containers/Bundle/Application/09D08A0A-0BC5-423C-8CC3-FF9499E0B19C
Application: /private/var/mobile/Containers/Bundle/Application/09D08A0A-0BC5-423C-8CC3-FF9499E0B19C/QR Reader.app
Data: /private/var/mobile/Containers/Data/Application/297EEF1B-9CC5-463C-97F7-FB062C864E56
```

ご覧のとおり、Bundle, Application, Data の三つの主要なディレクトリがあります。Application ディレクトリは Bundle ディレクトリのサブディレクトリです。
静的インストーラファイルは Application にありますが、すべてのユーザーデータは Data ディレクトリにあります。
URI のランダムな文字列はアプリケーションの GUID であり、インストールするごとに異なります。

##### インストールされたアプリから IPA ファイルを取り戻す

###### 脱獄デバイスから

Saurik の IPA インストーラを使用して、デバイスにインストールされたアプリから IPA を復元することができます。これを行うには、Cydia 経由で IPA installer console [1] をインストールします。次に、デバイスに ssh 接続して、ターゲットアプリのバンドル ID を調べます。

~~~
iPhone:~ root# ipainstaller -l
com.apple.Pages
com.example.targetapp
com.google.ios.youtube
com.spotify.client
~~~

以下のコマンドを使用して、IPA ファイルを生成します。

~~~
iPhone:~ root# ipainstaller -b com.example.targetapp -o /tmp/example.ipa
~~~

###### 非脱獄デバイスから

アプリが iTunes で利用可能な場合は、以下の簡単な手順で MacOS の ipa を復元できます。

- iTunes でアプリをダウンロードする
- iTunes の Apps Library にアクセスする
- アプリを右クリックし、finder で表示を選択する

-- TODO [Further develop section on Static Analysis of an iOS app from non-jailbroken devices without source code] --

#### 復号された実行可能ファイルのダンプ

コード署名の上に、App Store 経由で配布されるアプリも Apple の FairPlay DRM システムを使用して保護されています。このシステムでは非対称暗号を使用して App Store から取得した任意のアプリ (フリーのアプリを含みます) が、実行が承認された特定のデバイスでのみ実行されることを保証します。復号鍵はデバイス固有のもので、プロセッサに焼き付けられています。今のところ、FairPlayで復号化されたアプリから復号化されたコードを取得する唯一の方法は、アプリの実行中にメモリからダンプすることです。脱獄済みデバイスでは、これは標準の Cydia リポジトリに含まれている Clutch ツールで行うことができます [2] 。インタラクティブモードでクラッチを使用して、インストールされているアプリのリストを取得し、復号して IPA ファイルにパックします。

~~~
# Clutch -i 
~~~

**注意：** AppStore で配布されているアプリケーションのみが FairPlay DRM で保護されています。Xcode から直接コンパイルおよびエクスポートしたアプリケーションを取得した場合、復号化する必要はありません。もっとも簡単な方法は、アプリケーションを Hopper にロードして、それが正しく逆アセンブルされるか確認することです。otool で確認することもできます。

~~~
# otool -l yourbinary | grep -A 4 LC_ENCRYPTION_INFO
~~~

出力に cryptoff, cryptsize, cryptid フィールドが含まれている場合、バイナリは暗号化されています。このコマンドの出力が空の場合、バイナリは暗号化されていないことを意味します。IPA ファイルではなく、バイナリに対して otool を使用することを **忘れないで** ください。

#### class-dump と Hopper 逆アセンブラで基本情報の取得

class-dump ツールはアプリケーション内のメソッドに関する情報を取得できます。以下の例では Damn Vulnerable iOS アプリケーション [12] を使用しています。私たちのバイナリはいわゆるファットバイナリであり、32ビットと64ビットのプラットフォームで実行できます。

```
$ unzip DamnVulnerableiOSApp.ipa

$ cd Payload/DamnVulnerableIOSApp.app

$ otool -hv DamnVulnerableIOSApp 

DamnVulnerableIOSApp (architecture armv7):
Mach header
      magic cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
   MH_MAGIC     ARM         V7  0x00     EXECUTE    38       4292   NOUNDEFS DYLDLINK TWOLEVEL WEAK_DEFINES BINDS_TO_WEAK PIE

DamnVulnerableIOSApp (architecture arm64):
Mach header
      magic cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64   ARM64        ALL  0x00     EXECUTE    38       4856   NOUNDEFS DYLDLINK TWOLEVEL WEAK_DEFINES BINDS_TO_WEAK PIE

```

32ビットである `armv7` と `arm64` のアーキテクチャに注意します。この設計によりすべてのデバイスに同じアプリケーションをデプロイできます。
class-dump でアプリケーションを解析するには、ひとつのアーキテクチャのみを含む、いわゆるシンバイナリを作成する必要があります。

```
iOS8-jailbreak:~ root# lipo -thin armv7 DamnVulnerableIOSApp -output DVIA32
```

それから class-dump の実行に進みます。

```
iOS8-jailbreak:~ root# class-dump DVIA32 

@interface FlurryUtil : ./DVIA/DVIA/DamnVulnerableIOSApp/DamnVulnerableIOSApp/YapDatabase/Extensions/Views/Internal/
{
}
+ (BOOL)appIsCracked;
+ (BOOL)deviceIsJailbroken;
```

プラス記号は BOOL 型を返すクラスメソッドを意味することに注意します。
マイナス記号は、これがインスタンスメソッドであることを意味します。両者の実際的な違いを理解するには、以降のセクションを参照ください。

あるいは、Hopper 逆アセンブラ [13] でアプリケーションを簡単に逆コンパイルすることもできます。これらのすべての手順は自動的に実行され、逆アセンブルされたバイナリやクラス情報が表示されます。

静的解析を実行する際の主な焦点は以下のとおりです。
* 脱獄検出と証明書ピンニングを担当する機能の特定と理解
  * 脱獄検出には、`jailbreak`, `jailbroken`, `cracked` などの単語を含むメソッドやクラスを探します。脱獄検出を実行する関数の名前は解析を鈍化させるために「難読化」されることがあります。最善の策は以降のセクションで説明されている脱獄検出メカニズムを探すことです (動的解析 - 脱獄検出を参照ください) 。
  * 証明書ピンニングには、`pinning`, `X509` などのキーワードや `NSURLSession`, `CFStream`, `AFNetworking` などのネイティブメソッドコールを探します。
* アプリケーションロジックとそれを回避する可能性のある方法の理解
* ハードコードされた資格情報、証明書
* 難読化に使用され、結果として機密情報が明らかになる可能性がある任意のメソッド

### 動的解析

-- TODO [Dynamic analysis - copying data files, logs, from device, etc.] --

#### コンソールログの監視

多くのアプリは有益な (そして潜在的に機密の) メッセージをコンソールログに記録します。それ以外にも、ログにはクラッシュレポートや潜在的に有益な情報が含まれています。コンソールログは Xcode の "Devices" ウィンドウで以下のように収集できます。

1. Xcode を起動する
2. デバイスをホストコンピュータに接続する
3. デバイスを Window メニューから選択する
4. Devices ウィンドウの左側のセクションで、接続している iOS デバイスをクリックする
5. 問題を再現する
6. Devices の右側のセクションの左下隅にあるボックストグルの三角形をクリックする
コンソールログの内容を開示するウィンドウ

コンソール出力をテキストファイルに保存するには、右下の下向き矢印がついた円をクリックします。

![Console logs](Images/Chapters/0x06b/device_console.jpg "Monitoring console logs through XCode")

#### 脱獄済みデバイスでの動的解析

脱獄済みデバイスでのライフは簡単です。アプリのサンドボックスに簡単にアクセスできるだけでなく、コード署名の欠如のため、より強力な動的解析技法を使用することもできます。iOS では、ほとんどの動的解析ツールは Cydia Substrate 上に構築されています。このツールはランタイムパッチを開発するためのフレームワークです。これについては「改竄とリバースエンジニアリング」の章で詳しく説明します。しかし、基本的な API モニタリングの目的では、Substrate を詳しく知る必要はありません。この目的のために構築された既存のツールをそのまま使用できます。

##### アプリデータファイルのコピー

アプリに属するファイルはアプリのデータディレクトリに格納されます。正しいパスを特定するには、デバイスに ssh し、IPA インストーラコンソールを使用してパッケージ情報を取得します。

```bash
iPhone:~ root# ipainstaller -l 
sg.vp.UnCrackable-2
sg.vp.UnCrackable1

iPhone:~ root# ipainstaller -i sg.vp.UnCrackable1
Identifier: sg.vp.UnCrackable1
Version: 1
Short Version: 1.0
Name: UnCrackable1
Display Name: UnCrackable Level 1
Bundle: /private/var/mobile/Containers/Bundle/Application/A8BD91A9-3C81-4674-A790-AF8CDCA8A2F1
Application: /private/var/mobile/Containers/Bundle/Application/A8BD91A9-3C81-4674-A790-AF8CDCA8A2F1/UnCrackable Level 1.app
Data: /private/var/mobile/Containers/Data/Application/A8AE15EE-DC8B-4F1C-91A5-1FED35258D87
```

これでデータディレクトリをアーカイブし、scp を使用してデバイスから取り出すことができます。

```bash
iPhone:~ root# tar czvf /tmp/data.tgz /private/var/mobile/Containers/Data/Application/A8AE15EE-DC8B-4F1C-91A5-1FED35258D87
iPhone:~ root# exit
$ scp -P 2222 root@localhost:/tmp/data.tgz .
```

##### キーチェーンデータのダンプ

Keychain-Dumper [23] は脱獄済みデバイス上のキーチェーンの内容をダンプできます。ツールを実行する最も簡単な方法は GitHub リポジトリからバイナリをダウンロードすることです。

``` bash
$ git clone https://github.com/ptoomey3/Keychain-Dumper
$ scp -P 2222 Keychain-Dumper/keychain_dumper root@localhost:/tmp/
$ ssh -p 2222 root@localhost
iPhone:~ root# chmod +x /tmp/keychain_dumper
iPhone:~ root# /tmp/keychain_dumper 

(...)

Generic Password
----------------
Service: myApp
Account: key3
Entitlement Group: RUD9L355Y.sg.vantagepoint.example
Label: (null)
Generic Field: (null)
Keychain Data: SmJSWxEs

Generic Password
----------------
Service: myApp
Account: key7
Entitlement Group: RUD9L355Y.sg.vantagepoint.example
Label: (null)
Generic Field: (null)
Keychain Data: WOg1DfuH
```

但し、このバイナリは「ワイルドカード」エンタイトルメントの自己署名証明書で署名されていることに注意します。キーチェーンの *すべて* のアイテムへのアクセスを許可します。あなたが疑い深い場合やテストデバイスに機密性の高いプライベートデータを入れている場合、ツールをソースからビルドしてビルドに適切な資格を手作業で署名したいかもしれません。これを行うための説明はその GitHub リポジトリで利用可能です。

##### Introspy でのセキュリティプロファイリング

Intospy <sup>[31]</sup> は iSecPartners によりリリースされた iOS 用のオープンソースのセキュリティプロファイラです。substrate の上に構築されていて、脱獄済みデバイス上のセキュリティの影響を受けやすい API 呼び出しを記録するために使用できます。記録された API 呼び出しはコンソールに送られ、データベースファイルに書き込まれます。Introspy-Analyzer <code>[32]</code> を使用して HTML レポートに変換できます。

-- TODO [Write an IntroSpy howto] --

#### 非脱獄デバイス上での動的解析

脱獄済みデバイスにアクセスできない場合は、起動時にダイナミックライブラリをロードするためにターゲットアプリをパッチおよび再パッケージします。この方法では、アプリを計装し動的解析に必要なほとんどすべてを行うことができます (もちろん、その方法でサンドボックスを脱出することはできませんが、通常は必要ありません) 。但し、この技法はアプリバイナリが FairPlay 暗号化 (すなわち、App Store から取得) されていない場合にのみ機能します。

Apple のプロビジョニングとコード署名システムが混乱しているため、アプリの再署名は予想以上に困難です。プロビジョニングプロファイルとコード署名ヘッダが完全に正しい場合を除いて、iOS はアプリの実行を拒否します。これはあなたに多くの概念について学ぶことを要求します。さまざまなタイプの証明書、BundleID、アプリケーション ID、チーム識別子、Apple のビルドツールを使用してそれらを結びつける方法があります。言い換えれば、デフォルトの方法 (Xcode) を使用してビルドされていない特定のバイナリを OS に実行させることは厄介なプロセスになる可能性があります。

使用するツールセットは optool、Apple のビルドツール、いくつかのシェルコマンドで構成されています。私たちの方法は Vincent Tan の Swizzler プロジェクト [4] の resign スクリプトに触発されています。さまざまなツールを使用して再パッケージする別の方法が NCC グループにより記述されています [5] 。

下記の手順を再現するには、OWASP Mobile Testing Guide リポジトリ [6] から "UnCrackable iOS App Level 1" をダウンロードします。私たちの目標は、UnCrackable アプリが起動時に FridaGadget.dylib をロードして、Frida を使用してそれを計装できるようにすることです。

##### 開発用プロビジョニングプロファイルと証明書の取得

*プロビジョニングプロファイル* は Apple が署名した plist ファイルで、ひとつまたは複数のデバイスのコード署名証明書をホワイトリストに追加します。言い換えれば、これは Apple が選択したデバイス (開発プロファイル) でのデバッグなど、特定のコンテキストでアプリを明示的に実行できるように許可するものです。プロビジョニングプロファイルはアプリに付与された *エンタイトルメント* も含みます。*証明書* には実際の署名を行うために使用する秘密鍵を含みます。

iOS 開発者として登録しているかどうかに応じて、以下の二つの方法のいずれかを使用して証明書とプロビジョニングプロファイルを取得できます。

**iOS 開発者アカウントの場合：**

以前に Xcode を使用して iOS アプリを開発およびデプロイした場合、既に独自のコード署名証明書がインストールされています。*security* ツールを使用して、既存の署名識別子を一覧表示します。

~~~
$ security find-identity -p codesigning -v
  1) 61FA3547E0AF42A11E233F6A2B255E6B6AF262CE "iPhone Distribution: Vantage Point Security Pte. Ltd."
  2) 8004380F331DCA22CC1B47FB1A805890AE41C938 "iPhone Developer: Bernhard Müller (RV852WND79)"
~~~

Apple Developer ポータルにログインして新しい App ID を発行し、プロファイルを発行およびダウンロードします [8] 。App ID は何でもかまいません。同じ App ID を使用して、複数のアプリに再署名できます。アプリをデバッグできるようにするには、*development* プロファイルを作成することを確認します。*distribution* プロファイルではありません。

以下の例では、私の会社の開発チームに関連する独自の署名 ID を使用しています。この目的のために App ID "sg.vp.repackaged" と、"AwesomeRepackaging" という名前のプロビジョニングプロファイルを作成し、ファイル AwesomeRepackaging.mobileprovision にしました。これを以下のシェルコマンドで独自のファイル名と交換します。

**通常の iTunes アカウントの場合：**

幸いなことに、あなたが有料の開発者ではなくても、Apple はフリーの開発者プロビジョニングプロファイルを発行します。通常の Apple アカウントを使用して Xcode でプロファイルを取得することができます。空の iOS プロジェクトをビルドして、アプリコンテナから embedded.mobileprovision を抽出するだけです。NCC のブログでは、このプロセスを詳細に説明しています [5] 。

プロビジョニングプロファイルを取得したら、*security* ツールでその内容を確認できます。許可された証明書とデバイスに加えて、プロファイルにはアプリに付与されているエンタイトルメントがあります。コード署名には後でそれらが必要になりますので、以下に示すように別の plist ファイルに抽出します。また、ファイルの内容を見て、すべてが期待通りであるかどうかを確認することも重要です。

~~~
$ security cms -D -i AwesomeRepackaging.mobileprovision > profile.plist
$ /usr/libexec/PlistBuddy -x -c 'Print :Entitlements' profile.plist > entitlements.plist
$ cat entitlements.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>application-identifier</key>
	<string>LRUD9L355Y.sg.vantagepoint.repackage</string>
	<key>com.apple.developer.team-identifier</key>
	<string>LRUD9L355Y</string>
	<key>get-task-allow</key>
	<true/>
	<key>keychain-access-groups</key>
	<array>
		<string>LRUD9L355Y.*</string>
	</array>
</dict>
</plist>
~~~

application identitifier は Team ID (LRUD9L355Y) と Bundle ID (sg.vantagepoint.repackage) の組み合わせであることに注意します。このプロビジョニングプロファイルはこの特定の App ID を持つ一つのアプリに対してのみ有効です。"get-task-allow" key も重要です。"true" に設定する場合、デバッグサーバーなどの他のプロセスがアプリにアタッチすることが許可されます (結果的に、これはディストリビューションプロファイルでは "false" に設定されます) 。

##### その他の準備

起動時にアプリに追加のライブラリをロードさせるには、メインの実行可能ファイルの Mach-O ヘッダに追加の load コマンドをを挿入する方法が必要です。optool [3] を使用してこのプロセスを自動化できます。

~~~
$ git clone https://github.com/alexzielenski/optool.git
$ cd optool/
$ git submodule update --init --recursive
~~~

また、ios-deploy [10] も使用します。Xcode を使用せずに iOS アプリのデプロイとデバッグを可能にするツールです。

~~~
git clone https://github.com/alexzielenski/optool.git
cd optool/
git submodule update --init --recursive
~~~

以下の例に示すように、FridaGadget.dylib も必要です。

~~~
$ curl -O https://build.frida.re/frida/ios/lib/FridaGadget.dylib
~~~

上記のツールのほかに、OS X と Xcode に付属の標準ツールを使用します (Xcode コマンドライン開発者ツールがインストールされていることを確認します) 。

##### パッチ適用、再パッケージ化、再署名

本気になるときです。すでにご存知のとおり、IPA ファイルは実は ZIP アーカイブですので、任意の zip ツールを使用してアーカイブを展開します。その後、そのアプリディレクトリに FridaGadget.dylib をコピーし、optool を使用して "UnCrackable Level 1" バイナリに load コマンドを追加します。

~~~
$ unzip UnCrackable_Level1.ipa
$ cp FridaGadget.dylib Payload/UnCrackable\ Level\ 1.app/
$ optool install -c load -p "@executable_path/FridaGadget.dylib" -t Payload/UnCrackable\ Level\ 1.app/UnCrackable\ Level\ 1
Found FAT Header
Found thin header...
Found thin header...
Inserting a LC_LOAD_DYLIB command for architecture: arm
Successfully inserted a LC_LOAD_DYLIB command for arm
Inserting a LC_LOAD_DYLIB command for architecture: arm64
Successfully inserted a LC_LOAD_DYLIB command for arm64
Writing executable to Payload/UnCrackable Level 1.app/UnCrackable Level 1...
~~~

このような露骨な改竄はもちろんメインの実行可能ファイルのコード署名を無効にするため、これは非脱獄済みデバイスでは実行されません。プロビジョニングプロファイルを置き換え、メインの実行可能ファイルと FridaGadget.dylib の両方にそのプロファイルに記載されている証明書で署名する必要があります。

まず、独自のプロビジョニングプロファイルをパッケージに追加します。

~~~
$ cp AwesomeRepackaging.mobileprovision Payload/UnCrackable\ Level\ 1.app/embedded.mobileprovision
~~~

次に、Info.plist の BundleID がプロファイルに指定されているものと一致することを確認する必要があります。この理由は "codesign" ツールが署名時に Info.plist から Bundle ID を読み取るためです。間違った値は無効な署名につながります。

~~~
$ /usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier sg.vantagepoint.repackage" Payload/UnCrackable\ Level\ 1.app/Info.plist
~~~

最後に、codesign ツールを使用して、両方のバイナリを再署名します。

~~~
$ rm -rf Payload/F/_CodeSignature
$ /usr/bin/codesign --force --sign 8004380F331DCA22CC1B47FB1A805890AE41C938  Payload/UnCrackable\ Level\ 1.app/FridaGadget.dylib
Payload/UnCrackable Level 1.app/FridaGadget.dylib: replacing existing signature
$ /usr/bin/codesign --force --sign 8004380F331DCA22CC1B47FB1A805890AE41C938 --entitlements entitlements.plist Payload/UnCrackable\ Level\ 1.app/UnCrackable\ Level\ 1
Payload/UnCrackable Level 1.app/UnCrackable Level 1: replacing existing signature
~~~

##### アプリのインストールと実行

ここで改変されたアプリを実行するために設定する必要があります。以下のようにデバイス上にアプリをデプロイおよび実行します。

~~~
$ ios-deploy --debug --bundle Payload/UnCrackable\ Level\ 1.app/
~~~

すべてうまくいけば、lldb をアタッチしてデバッグモードでデバイス上でアプリを実行します。ここで Frida はアプリにアタッチできるはずです。これを確認するには、frida-ps コマンドを使用します。

~~~
$ frida-ps -U
PID  Name
---  ------
499  Gadget
~~~

![Frida on non-JB device](Images/Chapters/0x06b/fridaStockiOS.png "Frida on non-JB device")

##### トラブルシューティング

何かが間違っている (通常はそうなります) 場合、プロビジョニングプロファイルとコード署名ヘッダの間の不一致がもっとも疑われます。この場合、公式のドキュメントを読んでシステム全体の仕組みを理解することが有用です [7][8] 。Apple の entitlement トラブルシューティングページ [9] に役に立つリソースがあります。

### Burp のセットアップ

トラフィックをプロキシするように Burp をセットアップすることはとても簡単です。iDevice とワークステーションの両方が同じ Wi-Fi ネットワークに接続され、クライアントからクライアントへのトラフィックが許可されていることが前提となります。クライアントからクライアントへのトラフィックが許可されていない場合、usbmuxd [18] を使用して USB 経由で Burp に接続することが可能である必要があります。

最初のステップでは、すべてのインタフェース (または Wi-Fi インタフェースのみ) で listen するように Burp のプロキシを設定します。それから、高度な Wi-Fi 設定でプロキシを使用するように iDevice を設定します。Portswigger は iOS Device と Burp の設定に関するよいチュートリアルを提供しています [22] 。

### 証明書ピンニングのバイパス

証明書ピンニングは TLS 接続のセキュリティを強化するために使用される方法です。アプリケーションが TLS を使用してサーバーに接続する場合、サーバーの証明書が信頼できる CA の秘密鍵で署名されているかどうかがチェックされます。その検証はデバイスのキーストア内にある公開鍵で署名をチェックすることに基づいています。これにはすべての信頼できるルート CA の公開鍵が含まれています。

証明書ピンニングはアプリケーションがサーバーの証明書や証明書のハッシュをソースコード内にハードコードされることを意味します。
これは二つの主要な攻撃シナリオに対して保護します。

* 私たちのドメインの証明書をサードパーティに発行する不正な CA
* デバイスのトラストストアにサードパーティルート CA を追加するフィッシング攻撃

最も簡単な方法は `SSL Kill Switch` (Cydia ストア経由でインストール可能) を使用して、すべての高レベル API 呼び出しをフックし、証明書ピンニングをバイパスすることです。但し、証明書ピンニングはバイパスが難しい場合もあります。証明書ピンニングをバイパスしようとする際に探すべき事項は以下のとおりです。

- API 呼び出し： `NSURLSession`, `CFStream`, `AFNetworking`
- 静的解析の中で、'pinning', 'X509', 'Certificate' などの単語を含むメソッドや文字列を探してみます。
- 時には、openssl などを使用して、より低レベルの検証が行われます。これをバイパスする方法のチュートリアル [20] があります。
- Apache Cordova や Adobe Phonegap を使用して書かれた一部のデュアルスタックアプリケーションはコールバックを頻繁に使用します。成功したときに呼び出されるコールバック関数を探し、Cycript を使用して手動で呼び出します。
- 証明書がアプリケーションバンドル内にファイルとして存在することがあります。それを Burp の証明書で置き換えるだけで十分ですが、バイナリにハードコードされている可能性がある証明書の SHA サムに注意します。その場合はそれも置き換える必要があります。

#### 推奨事項

証明書ピンニングは適切なセキュリティプラクティスであり、機密情報を扱うすべてのアプリケーションで使用すべきです。
EFF の Observatory <sup>[28]</sup> は主要なオペレーティングシステムでデフォルトで信頼されているルート CA および中間 CA の一覧を提供します。Mozilla や Microsoft により (直接もしくは間接的に) 信頼された認証機関として機能する 650 異常の組織のマップも参照します <sup>[29]</sup> 。これらの CA のうち少なくともひとつを信頼しない場合には、証明書ピンニングを使用します。

ホワイトボックステストや一般的なコードパターンの詳細については David Thiel による iOS Application Security [21] を参照ください。証明書ピンニングを実行するために使用される最も一般的な技法の説明とコードスニペットが含まれています。

トランスポートセキュリティのテストの詳細については、「ネットワーク通信のテスト」のセクションを参照ください。

### 参考情報

* [1] IPA Installer Console - http://cydia.saurik.com/package/com.autopear.installipa
* [2] Clutch - https://github.com/KJCracks/Clutch
* [3] Optool - https://github.com/alexzielenski/optool
* [4] Swizzler 2 - https://github.com/vtky/Swizzler2/wiki
* [5] iOS instrumentation without jailbreak - https://www.nccgroup.trust/au/about-us/newsroom-and-events/blogs/2016/october/ios-instrumentation-without-jailbreak/
* [6] Uncrackable Level 1 - https://github.com/OWASP/owasp-mstg/tree/master/OMTG-Files/02_Crackmes/02_iOS/UnCrackable_Level1
* [7] Maintaining Certificates - https://developer.apple.com/library/content/documentation/IDEs/Conceptual/AppDistributionGuide/MaintainingCertificates/MaintainingCertificates.html
* [8] Maintaining Provisioning Profiles - https://developer.apple.com/library/content/documentation/IDEs/Conceptual/AppDistributionGuide/MaintainingProfiles/MaintainingProfiles.html
* [9] Entitlements Troubleshooting - https://developer.apple.com/library/content/technotes/tn2415/_index.html
* [10] iOS-deploy - https://github.com/phonegap/ios-deploy
* [11] MacOS and iOS Internals, Volume III: Security & Insecurity - Johnathan Levin
* [12] Damn Vulnerable iOS Application - http://damnvulnerableiosapp.com/
* [13] Hopper Disassembler - https://www.hopperapp.com/
* [14] Introduction to iOS Application Security Testing - Slawomir Kosowski
* [15] The Mobile Application Hacker's Handbook -  Dominic Chell, Tyrone Erasmus, Shaun Colley
* [16] Cydia Substrate  - http://www.cydiasubstrate.com
* [17] Frida - http://frida.re
* [18] usbmuxd - https://github.com/libimobiledevice/usbmuxd
* [19] Jailbreak Detection Methods - https://www.trustwave.com/Resources/SpiderLabs-Blog/Jailbreak-Detection-Methods/
* [20] Bypassing OpenSSL Certificate Pinning -https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2015/january/bypassing-openssl-certificate-pinning-in-ios-apps/ 
* [21] iOS Application Security - David Thiel
* [22] Configuring an iOS Device to Work With Burp - https://support.portswigger.net/customer/portal/articles/1841108-configuring-an-ios-device-to-work-with-burp
* [23] KeyChain-Dumper - https://github.com/ptoomey3/Keychain-Dumper/
* [24] iphonedevwiki - SSH over USB - http://iphonedevwiki.net/index.php/SSH_Over_USB
* [25] Can I Jailbreak? by IPSW Downloads - https://canijailbreak.com/
* [26] The iPhone Wiki - https://www.theiphonewiki.com/
* [27] The iPhone Wiki - https://www.theiphonewiki.com/wiki/Usbmux 
* [28] EFF's Observatory - https://www.eff.org/pl/observatory
* [29] Map of the 650-odd organizations that function as Certificate Authorities trusted (directly or indirectly) by Mozilla or Microsoft - https://www.eff.org/files/colour_map_of_CAs.pdf
* [30] IPSW Downloads - https://ipsw.me
* [31] IntroSpy - http://isecpartners.github.io/Introspy-iOS/
* [32] IntroSpy Analyzer - https://github.com/iSECPartners/Introspy-Analyzer
