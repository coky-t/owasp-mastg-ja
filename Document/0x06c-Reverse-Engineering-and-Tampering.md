## 改竄とリバースエンジニアリング (iOS)

### 環境とツールセット

-- TODO [Environment Overview] --

#### Xcode と iOS SDK

Xcode は macOS, iOS, watchOS, tvOS 用のソフトウェアを開発するために Apple が開発した一連のソフトウェア開発ツールを含む macOS 用の統合開発環境 (IDE) です。本書の執筆時点での最新リリースは Xcode 8 で、Apple の公式 Web サイト <sup>[7]</sup> からダウンロードできます。

以前 iPhone SDK として知られていた iOS SDK (ソフトウェア開発キット) は iOS 用のネイティブアプリケーションを開発するために Apple が開発したソフトウェア開発キットです。本書の執筆時点での最新リリースは iOS 10 SDK で、Apple の公式 Web サイト <sup>[8]</sup> からダウンロードできます。

#### ユーティリティ

- Steve Nygard <sup>[1]</sup> による Class-dump は Mach-O ファイルに格納された Objective-C ランタイム情報を調べるためのコマンドラインユーティリティです。クラス、カテゴリ、プロトコルの宣言を生成します。

- Class-dump-z <sup>[9]</sup> は動的コールの使用を避けるため C++ を使用してゼロから class-dump を書き直したものです。これらの不要なコールを削除することで class-dump-z はそれらより10倍近く高速になります。

- Elias Limneos <sup>[2]</sup> による Class-dump-dyld は共有キャッシュから直にシンボルをダンプおよび取得できるため、ファイルを最初に抽出する必要がありません。アプリバイナリ、ライブラリ、フレームワーク、バンドル、または dyld_shared_cache 全体からヘッダファイルを生成します。dyld_shared_cache 全体やディレクトリを再帰的に Mass-dump することもできます。

- MachoOView <sup>[3]</sup> は有用なビジュアル Mach-O ファイルブラウザで、ARM バイナリのインファイル編集も可能です。

- otool はオブジェクトファイルやライブラリの指定された部分を表示するためのツールです。これは Mach-O ファイルとユニバーサルファイルフォーマットの両方を理解します。

#### リバースフレームワーク

Radare2 はリバースエンジニアリングと解析のための完全なフレームワークです。これは Capstone 逆アセンブラ、Keystone アセンブラ、Unicorn CPU エミュレータエンジンを中心に構築されています。Radare2 はネイティブ Objective-C パーサーや iOS デバッガなど、iOS バイナリや多くの有用な iOS 固有の機能をサポートしています。

#### 商用逆アセンブラ

IDA Pro は iOS バイナリを扱うことができ、iOS デバッガを内蔵しています。IDA は GUI ベースでインタラクティブな静的解析のためのゴールドスタンダードとして広く知られていますが、安価ではありません。より予算を重視するリバースエンジニアには、Hopper が同様の静的解析機能を提供します。

### iOSの脱獄

iOS の世界では、脱獄とは Apple のコード署名メカニズムを無効にすることを意味しており、Apple が署名していないアプリを実行できます。iOS デバイスでどのような形式の動的セキュリティテストを行う場合でも、最も有用なテストツールはアプリストア以外でのみ利用可能であるため、脱獄済みデバイスでは作業がはるかに簡単になります。

任意のバージョンの iOS 向けに脱獄を開発することは簡単な努力ではありません。セキュリティテスト担当者としては、一般に公開されている脱獄ツールを使用したいと考えています(心配することはありません。私たちは皆、何かしらの領域ではスクリプトキディーなのです)。それでも、過去のさまざまなバージョンの iOS を脱獄するために使われる技法を学習することをお勧めします。非常に面白いエクスプロイトが多数あり、OS の内部について多くのことが学べます。例えば、 iOS 9.x 用の Pangu9 は、カーネルの use-after-free バグ(CVE-2015-6794)や写真アプリの任意のファイルシステムアクセスの脆弱性(CVE-2015-7037)など、少なくとも5つの脆弱性を悪用していました <sup>[4]</sup>。

脱獄用語での、紐付きおよび紐なし脱獄手法について説明します。「紐付き」シナリオでは、脱獄は再起動後には維持されませんので、再起動するたびにデバイスをコンピュータに接続(紐付き)して再適用する必要があります。「紐なし」脱獄は一度だけ適用すればよく、エンドユーザーにとって最も一般的な選択となっています。

iOS デバイスの脱獄の利点には以下のものなどがあります。

* Apple が課した OS のセキュリティ (およびその他) 制限を削除すること
* オペレーティングシステムへのルートアクセスを提供すること
* 重要なテストソフトウェアツールのインストールを許可すること
* Objective-C ランタイムへのアクセスを提供すること

iOS アプリケーションはアプリケーションサンドボックスにデータを格納します。それはパブリックにアクセス可能ではありません (しかしルートとアプリケーション自体は可能です) 。ルートアクセスでなければ、デバイスに格納されているデータやその格納方法を分析して、アプリケーションサンドボックスを評価することはできません。

#### iOSの脱獄の方法

iOS の脱獄のシーンは急速に変化しており、最新の説明を提供することは困難です。

iOS デバイスを文鎮化してしまっても、OWASP および MSTG はいかなる責任も負わないことに注意します。

iOS の脱獄に関するコンテンツについて読める信頼できるリソースです。

* The iPhone Wiki - https://www.theiphonewiki.com/wiki/Jailbreak
* Redmond Pie - http://www.redmondpie.com/
* Reddit Jailbreak - https://www.reddit.com/r/jailbreak/

#### 脱獄検出の扱い

一部のアプリはインストールされている iOS デバイスが脱獄済みであるかどうかを検出しようとします。この脱獄により iOS のデフォルトセキュリティメカニズムの一部を無効にするため、環境の信頼性低下につながります。

このアプローチの中核となるジレンマは、定義上、脱獄がアプリの環境を信頼できないものにすることです。デバイスが脱獄されているかどうかをテストするために使用される API を操作することができ、コード署名を無効にすると、脱獄検出コードを簡単に修正することができます。したがって、リバースエンジニアリングを妨げる非常に効果的な方法ではありません。それでも、脱獄検出はより大きなソフトウェア保護スキームの文脈において有用となります。このトピックは次の章で再考します。

### iOS アプリのリバースエンジニアリング

iOS reverse engineering is a mixed bag. On the one hand, apps programmed in Objective-C and Swift can be disassembled nicely. In Objective-C, object methods are called through dynamic function pointers called "selectors", which are resolved by name during runtime. The advantage of this is that these names need to stay intact in the final binary, making the disassembly more readable. Unfortunately, this also has the effect that no direct cross-references between methods are available in the disassembler, and constructing a flow graph is challenging. 

In this guide, we'll give an introduction on static and dynamic analysis and instrumentation. Throughtout this chapter, we'll be referring to the OWASP UnCrackable Apps for iOS, so download them from MSTG repository if you're planning to follow the examples.

#### 静的解析

-- TODO [iOS Static Analysis with examples] --

#### デバッグ

-- TODO [iOS Debugging Overview] --

iOS でのデバッグは一般的に Mach IPC を介して実装されます。ターゲットプロセスにアタッチするには、デバッガプロセスはターゲットプロセスのプロセス ID で <code>task_for_pid()</code> 関数を呼び出し、Mach ポートを受け取ります。その後、デバッガは例外メッセージのレシーバとして登録し、デバッグ対象で発生した例外の処理を開始します。Mach IPC はターゲットプロセスのサスペンド、レジスタステートや仮想メモリの読み書きなどのアクションを実行するために使用されます。

XNU カーネルは <code>ptrace()</code> システムコールも実装していますが、レジスタステートやメモリ内容を読み書きする機能などの一部の機能が削除されています。それでも、<code>lldb</code> や <code>gdb</code> などの標準的なデバッガでは <code>ptrace()</code> が限定的に使用されます。Radare2 の iOS デバッガなどの一部のデバッガは <code>ptrace</code> をまったく使用しません。

##### Using lldb

iOS にはコンソールアプリケーション debugserver が付属しており、gdb または lldb を使用したリモートでバッグが可能です。但し、デフォルトでは debugserver を任意のプロセスにアタッチすることはできません(通常は XCode でデプロイされた自己開発アプリのデバッグにのみ使用されます)。サードパーティアプリのデバッグを有効にするには、task_for_pid entitlement を debugserver 実行可能ファイルに追加する必要があります。これを行う簡単な方法は XCode に同梱されている debugserver バイナリに entitlement を追加することです <sup>[5]</sup>。

実行可能ファイルを取得するには以下の DMG イメージをマウントします。

~~~
/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/ DeviceSupport/<target-iOS-version//DeveloperDiskImage.dmg
~~~

debugserver 実行可能ファイルはマウントされたボリュームの /usr/bin/ ディレクトリにあります。一時ディレクトリにそれをコピーします。次に、以下の内容で entitlements.plist というファイルを作成します。

~~~
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/ PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.springboard.debugapplications</key>
	<true/>
	<key>run-unsigned-code</key>
	<true/>
	<key>get-task-allow</key>
	<true/>
	<key>task_for_pid-allow</key>
	<true/>
</dict>
</plist>
~~~

それから codesign で entitlement を適用します。

~~~
codesign -s - --entitlements entitlements.plist -f debugserver
~~~

変更したバイナリをテストデバイス上の任意のディレクトリにコピーします(以下の例では、usbmuxd を使用して USB 経由でローカルポートを転送しています)。

~~~
$ ./tcprelay.py -t 22:2222
$ scp -P2222 debugserver root@localhost:/tmp/
~~~

debugserver をデバイス上で動作する任意のプロセスにアタッチできるようになります。

~~~
VP-iPhone-18:/tmp root# ./debugserver *:1234 -a 2670
debugserver-@(#)PROGRAM:debugserver  PROJECT:debugserver-320.2.89
 for armv7.
Attaching to process 2670...
~~~

-- TODO [Solving UnCrackable App with lldb] --

##### Using Radare2

-- TODO [Write Radare2 tutorial] --

### 改竄と計装

#### MobileSubstrate でのフック

#### Cycript と Cynject

Cydia Substrate (formerly called MobileSubstrate) is the de-facto standard framework for developing run-time patches (“Cydia Substrate extensions”) on iOS. It comes with Cynject, a tool that provides code injection support for C. Cycript is a scripting language developed by Jay Freeman (saurik). Cycript injects a JavaScriptCore VM into the running process. Users can then manipulate the process using a hybrid of Objective-C++ and JavaScript syntax through the Cycript interactive console. It is also possible to access and instantiate Objective-C classes inside a running process. Some examples for the use of Cycript are listed in the iOS chapter.

Firt the SDK need to be downloaded, unpacked and installed.
```bash
$ wget https://cydia.saurik.com/api/latest/3 -O cycript.zip && unzip cycript.zip
#on iphone
$ sudo cp -a Cycript.lib/*.dylib /usr/lib
$ sudo cp -a Cycript.lib/cycript-apl /usr/bin/cycript
```
To spawn the interactive cycript shell, you can run “./cyript” or just “cycript” if cycript is on your path.
```bash
$ cycyript
cy#
```
To inject into a running process, we need to first find out the process ID (PID). We can run “cycript -p” with the PID to inject cycript into the process. To illustrate we will inject into springboard.
```bash
$ ps -ef | grep SpringBoard 
501 78 1 0 0:00.00 ?? 0:10.57 /System/Library/CoreServices/SpringBoard.app/SpringBoard
$ ./cycript -p 78
cy#
```
We have injected cycript into SpringBoard, lets try to trigger an alert message on SpringBoard with cycript. 		
```bash
cy# alertView = [[UIAlertView alloc] initWithTitle:@"OWASP MSTG" message:@"Mobile Security Testing Guide"  delegate:nil cancelButtonitle:@"OK" otherButtonTitles:nil]
#"<UIAlertView: 0x1645c550; frame = (0 0; 0 0); layer = <CALayer: 0x164df160>>"
cy# [alertView show]
cy# [alertView release]
```
![Cycript Alert Sample](Images/Chapters/0x06c/cycript_sample.png)

Discover the document directory with cycript:
```bash
cy# [[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask][0]
#"file:///var/mobile/Containers/Data/Application/A8AE15EE-DC8B-4F1C-91A5-1FED35212DF/Documents/"
```

Get the delegate class for the application using the command below:
```bash
cy# [UIApplication sharedApplication].delegate
```
The command [[UIApp keyWindow] recursiveDescription].toString() returns the view hierarchy of keyWindow. The description of every subview and sub-subview of keyWindow will be shown and the indentation space reflects the relationships of each views. For an example UILabel, UITextField and UIButton are subviews of UIView. 

```
cy# [[UIApp keyWindow] recursiveDescription].toString()
`<UIWindow: 0x16e82190; frame = (0 0; 320 568); gestureRecognizers = <NSArray: 0x16e80ac0>; layer = <UIWindowLayer: 0x16e63ce0>>
   | <UIView: 0x16e935f0; frame = (0 0; 320 568); autoresize = W+H; layer = <CALayer: 0x16e93680>>
   |    | <UILabel: 0x16e8f840; frame = (0 40; 82 20.5); text = 'i am groot!'; hidden = YES; opaque = NO; autoresize = RM+BM; userInteractionEnabled = NO; layer = <_UILabelLayer: 0x16e8f920>>
   |    | <UILabel: 0x16e8e030; frame = (0 110.5; 320 20.5); text = 'A Secret Is Found In The ...'; opaque = NO; autoresize = RM+BM; userInteractionEnabled = NO; layer = <_UILabelLayer: 0x16e8e290>>
   |    | <UITextField: 0x16e8fbd0; frame = (8 141; 304 30); text = ''; clipsToBounds = YES; opaque = NO; autoresize = RM+BM; gestureRecognizers = <NSArray: 0x16e94550>; layer = <CALayer: 0x16e8fea0>>
   |    |    | <_UITextFieldRoundedRectBackgroundViewNeue: 0x16e92770; frame = (0 0; 304 30); opaque = NO; autoresize = W+H; userInteractionEnabled = NO; layer = <CALayer: 0x16e92990>>
   |    | <UIButton: 0x16d901e0; frame = (8 191; 304 30); opaque = NO; autoresize = RM+BM; layer = <CALayer: 0x16d90490>>
   |    |    | <UIButtonLabel: 0x16e72b70; frame = (133 6; 38 18); text = 'Verify'; opaque = NO; userInteractionEnabled = NO; layer = <_UILabelLayer: 0x16e974b0>>
   |    | <_UILayoutGuide: 0x16d92a00; frame = (0 0; 0 20); hidden = YES; layer = <CALayer: 0x16e936b0>>
   |    | <_UILayoutGuide: 0x16d92c10; frame = (0 568; 0 0); hidden = YES; layer = <CALayer: 0x16d92cb0>>`
```

Obtain references to existing objects

TODO

Instantiate objects from classes

TODO

Hooking native functions

TODO

Hooking objective-C methods

TODO

Cycript tricks:

http://iphonedevwiki.net/index.php/Cycript_Tricks

#### Frida

-- TODO [Develop section on Frida] --

### 参考情報

-- TODO [Clean up References] --

* [1] Class-dump - http://stevenygard.com/projects/class-dump/
* [2] Class-dump-dyld - https://github.com/limneos/classdump-dyld/
* [3] MachOView - https://sourceforge.net/projects/machoview/
* [3] Jailbreak Exploits on the iPhone Dev Wiki - https://www.theiphonewiki.com/wiki/Jailbreak_Exploits#Pangu9_.289.0_.2F_9.0.1_.2F_9.0.2.29)
* [4] Stack Overflow - http://stackoverflow.com/questions/413242/how-do-i-detect-that-an-ios-app-is-running-on-a-jailbroken-phone
* [5] Debug Server on the iPhone Dev Wiki - http://iphonedevwiki.net/index.php/Debugserver
* [6] Uninformed - Replacing ptrace() - http://uninformed.org/index.cgi?v=4&a=3&p=14
* [7] Apple Xcode IDE - https://developer.apple.com/xcode/ide/
* [8] Apple iOS 10 SDK - https://developer.apple.com/ios/
* [9] Class-dump-z - https://code.google.com/archive/p/networkpx/wikis/class_dump_z.wiki


- [x] IDA Pro - https://www.hex-rays.com/products/ida/
