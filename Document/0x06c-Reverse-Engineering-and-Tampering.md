## 改竄とリバースエンジニアリング (iOS)

### 環境とツールセット

-- TODO [Environment Overview] --

#### XCode と iOS SDK

-- TODO [Where to get XCode] --

#### ユーティリティ

Steve Nygard [1] による Class-dump は Mach-O ファイルに格納された Objective-C ランタイム情報を調べるためのコマンドラインユーティリティです。クラス、カテゴリ、プロトコルの宣言を生成します。

Elias Limneos [2] による Class-dump-dyld は共有キャッシュから直にシンボルをダンプおよび取得できるため、ファイルを最初に抽出する必要がありません。アプリバイナリ、ライブラリ、フレームワーク、バンドル、または dyld_shared_cache 全体からヘッダファイルを生成します。dyld_shared_cache 全体やディレクトリを再帰的に Mass-dump することもできます。

MachoOView [3] は有用なビジュアル Mach-O ファイルブラウザで、ARM バイナリのインファイル編集も可能です。

### iOSの脱獄

iOS の世界では、脱獄とは Apple のコード署名メカニズムを無効にすることを意味しており、Apple が署名していないアプリを実行できます。iOS デバイスでどのような形式の動的セキュリティテストを行う場合でも、最も有用なテストツールはアプリストア以外でのみ利用可能であるため、脱獄済みデバイスでは作業がはるかに簡単になります。

任意のバージョンの iOS 向けに脱獄を開発することは簡単な努力ではありません。セキュリティテスト担当者としては、一般に公開されている脱獄ツールを使用したいと考えています(心配することはありません。私たちは皆、何かしらの領域ではスクリプトキディーなのです)。それでも、過去のさまざまなバージョンの iOS を脱獄するために使われる技法を学習することをお勧めします。非常に面白いエクスプロイトが多数あり、OS の内部について多くのことが学べます。例えば、 iOS 9.x 用の Pangu9 は、カーネルの use-after-free バグ(CVE-2015-6794)や写真アプリの任意のファイルシステムアクセスの脆弱性(CVE-2015-7037)など、少なくとも5つの脆弱性を悪用していました [3]。

脱獄用語での、紐付きおよび紐なし脱獄手法について説明します。「紐付き」シナリオでは、脱獄は再起動後には維持されませんので、再起動するたびにデバイスをコンピュータに接続(紐付き)して再適用する必要があります。「紐なし」脱獄は一度だけ適用すればよく、エンドユーザーにとって最も一般的な選択となっています。

-- TODO [Jailbreaking howto] --

一部のアプリはインストールされている iOS デバイスが脱獄済みであるかどうかを検出しようとします。この脱獄により iOS のデフォルトセキュリティメカニズムの一部を無効にするため、環境の信頼性低下につながります。

このアプローチの中核となるジレンマは、定義上、脱獄がアプリの環境を信頼できないものにすることです。デバイスが脱獄されているかどうかをテストするために使用される API を操作することができ、コード署名を無効にすると、脱獄検出コードを簡単に修正することができます。したがって、リバースエンジニアリングを妨げる非常に効果的な方法ではありません。それでも、脱獄検出はより大きなソフトウェア保護スキームの文脈において有用となります。また、MASVS L2 では脱獄検出されたときにユーザーに警告を表示したりアプリを終了させたりする必要があります。ここでのアイデアはデバイスを脱獄することを選択することでの潜在的なセキュリティへの影響(および積極的なリバースエンジニアを妨げるものではないこと)についてユーザーに通知することです。

このトピックは「リバースエンジニアリングに対する耐性のテスト」の章で再考します。

### iOS アプリのリバースエンジニアリング

-- TODO [Overview] --

#### 静的解析

-- TODO [Basic static analysis ] --

#### デバッグ

-- TODO [iOS Debugging Overview] --

iOS でのデバッグは一般的に Mach IPC を介して実装されます。ターゲットプロセスにアタッチするには、デバッガプロセスはターゲットプロセスのプロセス ID で <code>task_for_pid()</code> 関数を呼び出し、Mach ポートを受け取ります。その後、デバッガは例外メッセージのレシーバとして登録し、デバッグ対象で発生した例外の処理を開始します。Mach IPC はターゲットプロセスのサスペンド、レジスタステートや仮想メモリの読み書きなどのアクションを実行するために使用されます。

XNU カーネルは <code>ptrace()</code> システムコールも実装していますが、レジスタステートやメモリ内容を読み書きする機能などの一部の機能が削除されています。それでも、<code>lldb</code> や <code>gdb</code> などの標準的なデバッガでは <code>ptrace()</code> が限定的に使用されます。Radare2 の iOS デバッガなどの一部のデバッガは <code>ptrace</code> をまったく使用しません。

##### Using lldb

-- TODO [Complete lldb tutorial] --

iOS にはコンソールアプリケーション debugserver が付属しており、gdb または lldb を使用したリモートでバッグが可能です。但し、デフォルトでは debugserver を任意のプロセスにアタッチすることはできません(通常は XCode でデプロイされた自己開発アプリのデバッグにのみ使用されます)。サードパーティアプリのデバッグを有効にするには、task_for_pid entitlement を debugserver 実行可能ファイルに追加する必要があります。これを行う簡単な方法は XCode に同梱されている debugserver バイナリに entitlement を追加することです [5]。

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

##### Using Radare2

-- TODO [Write Radare2 tutorial] --

### 改竄と計装

#### MobileSubstrate でのフック

#### Cycript と Cynject

Cydia Substrate (旧称 MobileSubstrate) は iOS 上でランタイムパッチ(「Cydia Substrate extensions」)を開発するためのデファクトスタンダードのフレームワークです。これには C のコードインジェクションをサポートするツールである Cynject が付属します。iOS で実行中のプロセスに JavaScriptCore VM を注入することにより、ユーザーは C コードとインタフェースすることができます。プリミティブ型、ポインタ、構造体、C 文字列、および Objective-C オブジェクトやデータ構造をサポートします。また、実行中のプロセス内の Objective-C クラスにアクセスしてインスタンス化することもできます。Cycript の使用例は iOS の章に記載されています。

Cycript は実行中のプロセスに JavaScriptCore VM を注入します。ユーザーは拡張構文を持つ JavaScript を使用して Cycript Console 経由でプロセスを操作することができます

-- TODO [Add use cases and example for Cycript] --

- 既存オブジェクトのリファレンスを取得する
- クラスからオブジェクトをインスタンス化する
- ネイティブ関数をフックする
- Objective-C メソッドをフックする
- などなど
http://www.cycript.org/manual/

Cycript tricks:

http://iphonedevwiki.net/index.php/Cycript_Tricks

#### Frida

-- TODO [Develop section on Frida] --

### 参考情報

- [1] Class-dump - http://stevenygard.com/projects/class-dump/
- [2] Class-dump-dyld - https://github.com/limneos/classdump-dyld/
- [3] MachOView - https://sourceforge.net/projects/machoview/
- [3] Jailbreak Exploits on the iPhone Dev Wiki - https://www.theiphonewiki.com/wiki/Jailbreak_Exploits#Pangu9_.289.0_.2F_9.0.1_.2F_9.0.2.29)
- [4] Stack Overflow - http://stackoverflow.com/questions/413242/how-do-i-detect-that-an-ios-app-is-running-on-a-jailbroken-phone
- [5] Debug Server on the iPhone Dev Wiki - http://iphonedevwiki.net/index.php/Debugserver
- [6] Uninformed - Replacing ptrace() - http://uninformed.org/index.cgi?v=4&a=3&p=14
