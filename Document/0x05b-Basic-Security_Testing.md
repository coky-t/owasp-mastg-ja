## セキュリティテスト入門 (Android)

### テスト環境のセットアップ

テスト環境をセットアップする場合、これは困難な作業になる可能性があります。例えば、クライアントの敷地内でオンサイトでテストする場合、作成できる接続の制限 (ポートがブロックされているなど) により、エンタープライズアクセスポイントを使用する際に制限があるため、アプリの動的解析を開始することがより困難になります。ルート化された電話は企業ポリシーによりエンタープライズネットワーク内で許可されないこともあります。また、アプリ内で実装されるルート検出やその他の対策は、最終的にアプリをテストできるようにするために、余計な作業につながる可能性があります。いずれにしても、Android 評価を担当するテストチームはアプリ開発者や運用チームと協力して、作業するテスト環境として最適なソリューションを見つける必要があります。

このセクションでは Android アプリのテスト方法に関するさまざまな手法の概要を説明し、その制限についても説明します。上記の理由により、テスト環境に適したものを選択するために、すべての可能なテスト手法について注意する必要があります。また、プロジェクトの全員が同じ考えを持つようにするため、制限を明示します。

#### 準備

セキュリティテストには、モバイルアプリとそのリモートエンドポイント間のネットワークトラフィックの監視や操作、アプリのデータファイルの検査、API コールの計装など、多くの侵入的な作業が含まれます。SSL ピンニングやルート検出などのセキュリティコントロールはこれらの作業を妨げ、テストを大幅に遅くする可能性があります。

準備フェーズでは、そのモバイルアプリを開発している会社と二つのバージョンのアプリを提供することについて話し合う必要があります。ひとつのアプリはリリースとしてビルドし、SSL ピンニングなどの実装されたコントロールが適切に動作しているかや容易にバイパスできるかを確認する必要があります。また、同じアプリはデバッグビルドとして提供され、特定のセキュリティコントロールを無効化する必要があります。このアプローチにより、すべてのシナリオとテストケースを最も効率的な方法でテストできます。

このアプローチでは取り決めの範囲に合わせる必要があります。ブラックボックステストやホワイトボックステストの場合、詳細については前述の「静的解析」セクションを参照ください。ホワイトボックステストでは、プロダクションとデバッグビルドをリクエストすると、すべてのテストケースを通して、アプリのセキュリティ成熟度を明確に説明するのみ役立ちます。ブラックボックステストでは、プロダクションアプリで一定時間内に何ができるかや、実装されたセキュリティコントロールがどのくらい効果的であるかを見ることがクライアントの意図である可能性があります。

いずれにしても、以下の項目についてモバイルアプリと議論する必要があり、実装されたセキュリティコントロールを調整して、テスト作業を最大限に活用できるかどうかを判断する必要があります。

##### OS バージョン

アプリケーションのテストを開始する前に、必要なハードウェアとソフトウェアをすべて用意することが重要です。これは検査ツールを実行する準備が整ったマシンを用意するだけでなく、正しいバージョンの Android OS がテストデバイスにインストールされていることも意味します。したがって、アプリケーションが特定のバージョンの Android OS でのみ動作するかどうかを尋ねることを常に推奨します。

#### 実デバイスでのテスト

モバイルアプリの動的解析を開始する前に、さまざまな準備手順を適用する必要があります。理想的にはデバイスはルート化されています。そうでなければいくつかのテストケースを適切にテストできません。詳細については「デバイスのルート化」を参照ください。

ネットワーク用に利用可能なセットアップオプションを最初に評価する必要があります。テストに使用されるモバイルデバイスと傍受プロキシを実行するマシンは同じ WiFi ネットワーク内に配置する必要があります。(既存の) アクセスポイントが使用されるか、アドホックワイヤレスネットワークを作成します <sup>[3]</sup> 。

ネットワークが構成され、テストマシンとモバイルデバイスとの間に接続が確立されたら、いくつかの他の手順を実行する必要があります。

* Android デバイスのネットワーク設定のプロキシは、使用する傍受プロキシを指すように正しく設定する必要があります <sup>[1]</sup> 。
* 傍受プロキシの CA 証明書は Android デバイスの証明書ストレージ <sup>[2]</sup> の信頼できる証明書に追加する必要があります。さまざまなバージョンの Android と、Android OEM の設定メニューの変更のため、CA を格納するためのメニューの場所は異なる可能性があります。

これらの手順を完了してアプリを起動すると、リクエストが傍受プロキシに表示されます。


##### デバイスのルート化

###### ルート化のリスク

セキュリティテスト担当者として、モバイルデバイスのルート化を望むかもしれません。一部のテストは非ルート化デバイスで実行できますが、一部はルート化したものを必要とします。しかし、ルート化は簡単なプロセスではなく、高度な知識を要するという事実に注意が必要です。ルート化にはリスクがあり、進める前に三つの主要な影響を明らかにする必要があります。
* 通常はデバイスの保証を無効にします (何らかの措置をとる前に製造業者のポリシーを必ず確認します) 。
* デバイスを「文鎮化」する可能性があります。例えば、操作不能かつ使用不可にします。
* 組込まれているエクスプロイト対策がしばしば削除されるため、セキュリティリスクが増加します。

**デバイスをルート化することは最終的にあなた自身の判断であり、OWASP はいかなる損害に対しても一切の責任を負わないことを理解する必要があります。確信が持てない場合には、ルート化プロセスを開始する前に必ず専門家のアドバイスを求めます。**

###### どのモバイルがルート化できるのか

実質的には、どの Android モバイルでもルート化できます。商用バージョンの Android OSは、Linux OS のカーネルレベルの進化で、モバイルの世界に最適化されています。ここではいくつかの機能が削除または無効にされています。特権を持たないユーザーが (特権を持つ) 'root' ユーザーになる可能性などです。電話機のルート化はルートユーザーになる機能を追加することを意味します。例えば、技術的にはユーザーを切り替えるために使用される 'su' と呼ばれる標準の Linux 実行可能ファイルを追加するという話です。

モバイルをルート化する最初の手順はブートローダーをアンロックすることです。手続きは各製造業者により異なります。しかし、実用的な理由から、特にセキュリティテストに関しては、一部のモバイルのルート化は他のルート化よりも人気があります。Google 製 (および Samsung, LG, Motorola などの他社製) のデバイスは、特に開発者に広く使用されているため、最も人気があります。ブートローダーがアンロックされ、ルート化デバイスを使用するために Google がルート自体をサポートする多くのツールを提供している場合、デバイスの保証は無効になりません。すべての主要なブランドのデバイスのルート化に関するガイドの精選された一覧は xda フォーラムにあります <sup>[21]</sup> 。

詳細については「Android プラットフォーム概要」も参照ください。

##### 非ルート化デバイスを使用する場合の制限事項

Android アプリをテストするために、ルート化デバイスはテスト担当者がすべての利用可能なテストケースを実行できるようにするための基礎となります。非ルート化デバイスを使用する必要がある場合、依然としてアプリのいくつかのテストケースを実行することは可能です。

それでも、これはアプリでの制限や設定に大きく依存します。例えば、バックアップが許可されている場合、アプリのデータディレクトリのバックアップを抽出できます。これにより、アプリを使用するときに機密データの漏洩を詳細に分析できます。また、SSL ピンニングが使用されていない場合、非ルート化デバイスで動的解析を実行することもできます。

#### エミュレータでのテスト

ハードウェアテストデバイスを準備する上述のすべての手順は、エミュレータが使用される場合にも適用されます <sup>[4]</sup> 。動的テストの場合、エミュレータ環境内でアプリをテストするために使用できるいくつかのツールや VM があります。

* AppUse
* MobSF

単に AVD を作成して、これをテストに使用することもできます。

##### 仮想デバイスでの Web プロキシのセットアップ

エミュレータで HTTP プロキシをセットアップするには、Android Studio 2.x に付属の Android エミュレータで動作する以下の手順に従います。

1. localhost で listen するようにプロキシをセットアップします。プロキシポートをエミュレータからホストへリバースフォワードします。以下に例を示します。

```bash
$ adb reverse tcp:8080 tcp:8080
```

2. デバイスのアクセスポイント設定で HTTP プロキシを設定します。
- Settings メニューを開く
- "Wireless & Networks" -> "Cellular Networks" または "Mobile Networks" をタップする
- "Access Point Names" を開く
- 既存の APN ("T-Mobile US" など) を開く
- "Proxy" フィールドに "127.0.0.1" を入力し、"Port" フィールドにプロキシポートを入力する ("8080" など)
- 右上のメニューを開き "save" をタップする

<img width=300px src="Images/Chapters/0x05b/emulator-proxy.jpg"/>

HTTP および HTTPS リクエストはホストマシン上のプロキシ経由でルーティングされるようになりました。もし動作しない場合には、機内モードをオフおよびオンに切り替えてみます。

##### 仮想デバイスへの CA 証明書のインストール

CA 証明書をインストールする簡単な方法は、デバイスに証明書をプッシュし、セキュリティ設定で証明書ストアに証明書を追加することです。例えば、以下のように PortSwigger (Burp) CA 証明書をインストールできます。

1. Burp を起動し、ホスト上のウェブブラウザを使用して http://burp/ に移動し、"CA Certificate" ボタンをクリックして cacert.der をダウンロードします。
2. ファイル拡張子を .der から .cer に変更します。
3. ファイルをエミュレータにプッシュします。

```bash
$ adb push cacert.cer /sdcard/
```

4. "Settings" -> "Security" -> "Install from SD Card" に移動します
5. 下にスクロールし、"cacert.cer" をタップします

証明書のインストールを確認するメッセージが表示されるはずです (まだデバイスの PIN を設定していない場合、設定するよう求められます) 。

##### Android 仮想デバイス (AVD) にルートとして接続する

Android 仮想デバイス (AVD) は Android Studio で利用可能な AVD manager を使用して作成できます <sup>[5]</sup> 。AVD manager は Android SDK の tools ディレクトリにある `android` コマンドを使用して、コマンドラインから個別に起動することもできます。

```bash
$ ./android avd
```

エミュレータが起動して実行されると、`adb` を使用してルート接続を確立できます。

```bash
$ adb root
$ adb shell
root@generic_x86:/ $ id
uid=0(root) gid=0(root) groups=0(root),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats) context=u:r:su:s0
```

`adb` を通してルートアクセスが許可されるため、エミュレータのルート化は必要ありません。

##### エミュレータ上でテストする際の制限事項

エミュレータを使用する場合、いくつかの不都合な点があります。特定のモバイルネットワークの使用に依存する場合や、NFC や Bluetooth を使用する場合は、エミュレータでアプリを正しくテストできない可能性があります。エミュレータ内でのテストは通常本質的に遅く、独自の問題につながる可能性があります。

それでも、GPS <sup>[6]</sup> や SMS <sup>[7]</sup> など、いくつかのハードウェア特性をエミュレートしています。


#### 潜在的な障壁

テストしようとしているアプリに実装される可能性のある以下のセキュリティコントロールについて、デバッグビルドを提供できるかどうかプロジェクトチームと協議する必要があります。(ホワイトボックス) テストの中で提供される場合、より包括的な解析できるため、デバッグビルドにはいくつかの利点があります。

##### SSL ピンニング

SSL ピンニングは動的解析を難しくするメカニズムです。中間者ポジションを有効にするために傍受プロキシにより提供された証明書は却下され、アプリはリクエストしません。ホワイトボックステストの中で効率的にテストできるようにするには、SSL ピンニングを無効化したデバッグビルドを提供する必要があります。

ブラックボックステストでは、SSLUnpinning <sup>[11]</sup> や Android-SSL-TrustKiller <sup>[12]</sup> など SSL ピンニングをバイパスする方法がいくつかあります。バイパスは数秒でできるため、これらのツールで扱う API 機能をアプリが使用する場合にのみ使用可能です。これらのツールでまだ実装されていない SSL ピンニングを実装するため、アプリが異なるフレームワークやライブラリを使用している場合は、SSL ピンニングのパッチ適用および非アクティブ化を手作業で行う必要があり、時間がかかる可能性があります。

SSL ピンニングを手動で非アクティブ化するには、二つの方法があります。
* アプリ実行中の動的パッチ適用、Frida <sup>[9] [13]</sup> や ADBI<sup>[10]</sup> を使用します
* APK を逆アセンブリし、smali コードの SSL ピンニングロジックを特定し、パッチを適用して APK を再アセンブルします <sup>[7] [22]</sup>

成功すると、動的解析の前提条件が満たされ、アプリの通信を調査できます。

詳細についてはテストケース「カスタム証明書ストアと SSL ピンニングのテスト」も参照ください。

##### ルート検出

ルート検出は RootBeer <sup>[14]</sup> などの既成のライブラリやカスタムチェックなどを使用して実装できます。ルート検出手法の広範囲にわたるリストは「アンチリバース防御のテスト (Android)」の章に示されています。

典型的なモバイルアプリのセキュリティテストでは、一般的にルート検出を無効にしたデバッグビルドをテストします。そのようなビルドがテストで利用できない場合、ルート検出は本書で後述するさまざまな方法を使用して無効にできます。

### テスト手法

#### 静的解析

静的解析とはアプリコンポーネント、ソースコード、その他のリソースを実際に実行することなく調べる行為です。このテストでは誤って設定されていたり、保護されていない Android IPC コンポーネントの発見、暗号ルーチンの誤用などのプログラミングミスの発見、既知の脆弱性のあるライブラリの発見、さらに動的なコードローディングルーチンの発見に焦点を当てています。

静的解析はツールを使用してサポートすべきであり、解析を効率的にし、テスト担当者がより複雑なビジネスロジックに集中できるようにします。オープンソーススキャナから本格的なエンタプライズ対応のスキャナまでさまざまな静的コードアナライザが使用できます。どのツールを使用するかの判断は予算、顧客の要件、テスト担当者の好みに依存します。

静的アナライザにはソースコードを使用するものと、コンパイルされた APK を入力とするものがあります。
静的アナライザは潜在的な問題に注意を向けるのに役立ちますが、単独ですべての問題を見つけられるわけではないことに注意することが重要です。発見したそれぞれを慎重に調査し、アプリが何を行っているか理解して、脆弱性発見のチャンスを向上させます。

注意すべき重要な点の一つは誤検出の可能性を減らすために静的アナライザを適切に設定することであり、スキャンの脆弱性カテゴリのいくつかだけを選択するかもしれません。さもなくば、静的アナライザにより生成される結果が過多となる可能性があり、過度に大きなレポートを手作業で調べる必要がある場合にはその労力は逆効果となりえます。

静的解析は **ホワイトボックス** と **ブラックボックス** の二つのカテゴリに分類できます。前者はソースコードが利用可能である場合で、後者はコンパイルされたアプリケーションやライブラリのみがある場合です。それぞれのカテゴリの詳細について説明します。

##### ソースコードありでの静的解析 ("ホワイトボックス")

アプリの **ホワイトボックステスト** は利用可能なソースコードでアプリをテストする行為です。ソースコードのテストを行うには、開発者と同様のセットアップをすることが望まれます。Android SDK と IDE がインストールされたマシン上にテスト環境が必要です。また、物理デバイスまたはエミュレータにアクセスして、アプリをデバッグできるようにすることをお勧めします。

セットアップが完了し、ソースコードが IDE (Android Studio が推奨されています、これは Google が現在選択している IDE です) にインデックスされると、関心のある部分のコードのデバッグおよび検索を始められます。
それぞれの [Android コンポーネント](0x05a-Platform-Overview.md#アプリコンポーネント) をテストすることからはじめます。それらがエクスポートされているかどうか、および所定のパーミッションを施行していることを確認します。Android Lint <sup>[15]</sup> がそのような問題の特定に役立ちます。機密データ (連絡先、位置情報、画像など) を操作するすべての Android コンポーネントを慎重に調査する必要があります。

アプリケーションに組み込まれているライブラリのテストに進みます。一部のライブラリには既知の脆弱性があり、それを確認する必要があります。回答すべき質問は次のとおりです。アプリが使用しているライブラリはなんですか？どのバージョンのライブラリを使用していますか？それらには既知の脆弱性はありますか？

手元にソースコードがあるため、実装での暗号の間違いを確認できます。ハードコードされた鍵や暗号化機能に関連する実装エラーを探します。Devknox <sup>[16]</sup> は IDE に組み込まれているため、最も一般的な暗号の間違いを確認するのに役立ちます。

##### ソースコードなしでの静的解析 ("ブラックボックス")

**ブラックボックステスト**では、オリジナルの形式のソースコードにアクセスしません。通常、あなたは (Android .apk 形式 <sup>[17]</sup> の) アプリケーションパッケージを手にしており、Android デバイスにインストールすることや、ソースコードの一部を取得する目的でリバースエンジニアリングすることも可能です。

CLI で APK のソースコードを取得する簡単な方法は <code>apkx</code> を通すことです。<code>dex2jar</code> と CFR をパッケージ化しており、抽出、変換、逆コンパイルの手順を自動化します。以下のようにインストールします。

```
$ git clone https://github.com/b-mueller/apkx
$ cd apkx
$ sudo ./install.sh
```

これは <code>apkx</code> を <code>/usr/local/bin</code> にコピーします。テストする必要のある APK でそれを実行します。

```bash
$ apkx UnCrackable-Level1.apk
Extracting UnCrackable-Level1.apk to UnCrackable-Level1
Converting: classes.dex -> classes.jar (dex2jar)
dex2jar UnCrackable-Level1/classes.dex -> UnCrackable-Level1/classes.jar
Decompiling to UnCrackable-Level1/src (cfr)
```

アプリケーションは Java のみをベースにしており、ネイティブライブラリ (C/C++ で書かれたコード) を持たない場合、リバースエンジニアリングプロセスは比較的簡単で、ほとんどすべてのソースコードを復元します。しかしながら、コードが難読化されている場合、このプロセスは非常に時間がかかり、生産的ではなくなる可能性があります。同じことがネイティブライブラリを含むアプリケーションにも当てはまります。それらは依然としてリバースエンジニアリングできますが、低レベルの知識を必要とし、プロセスは自動化されません。

Android リバースエンジニアリングのトピックに関する詳細やツールは[改竄とリバースエンジニアリング (Android)](0x05c-Reverse-Engineering-and-Tampering.md) セクションにあります。

リバースエンジニアリングのほかにも、脆弱性を検索するために APK のセキュリティ解析を実行する自動ツールがいくつかあります。
これらのツールの一部は以下の通りです。
* QARK<sup>[18]</sup>
* Androbugs<sup>[19]</sup>
* JAADAS<sup>[20]</sup>

#### 動的解析

静的解析と比較して、動的解析はモバイルアプリの実行中に適用されます。テストケースは、モバイルデバイスのファイルシステムとその変更を調べることから、アプリ使用中のエンドポイントとの通信を監視することまでさまざまです。

HTTP(S) プロトコルに依存するアプリケーションの動的解析について言及するとき、いくつかのツールを使用して、動的解析をサポートできます。もっとも重要なツールは傍受プロキシと呼ばれ、もっとも有名なものとして OWASP ZAP や Burp Suite Professional などがあります。傍受プロキシはテスト担当者に中間者のポジションをあたえ、認証やセッション管理などをテストするために、アプリから作られたすべてのリクエストとエンドポイントから返されたレスポンスを読み取りもしくは変更することができます。

#### Drozer

Drozer<sup>[25]</sup> は Android セキュリティ評価フレームワークであり、他のアプリケーションの IPC エンドポイントや基盤となる OS と相互作用するサードパーティアプリの役割を前提として、アプリやデバイスのセキュリティ脆弱性を探します。以下のセクションでは Drozer をインストールおよび使用するために必要な手順について説明します。

##### Installing Drozer

###### Building from Source

```
git clone https://github.com/mwrlabs/drozer/
cd drozer
make apks
source ENVIRONMENT
python setup.py build
sudo env "PYTHONPATH=$PYTHONPATH:$(pwd)/src" python setup.py install
```

###### Installing .egg

```
sudo easy_install drozer-2.x.x-py2.7.egg
```

###### Building for Debian/Ubuntu

```
sudo apt-get install python-stdeb fakeroot
git clone https://github.com/mwrlabs/drozer/
cd drozer
make apks
source ENVIRONMENT
python setup.py --command-packages=stdeb.command bdist_deb

```

###### Installing .deb (Debian/Ubuntu)

```
sudo dpkg -i deb_dist/drozer-2.x.x.deb
```

###### Installing on Arch Linux

`yaourt -S drozer`

##### Installing the Agent

Drozer can be installed using Android Debug Bridge (adb).

Download the latest Drozer Agent [here](https://github.com/mwrlabs/drozer/releases/).

`$ adb install drozer-agent-2.x.x.apk`

##### Starting a Session

You should now have the Drozer console installed on your PC, and the Agent running on your test device. Now, you need to connect the two and you’re ready to start exploring.

We will use the server embedded in the Drozer Agent to do this.

If using the Android emulator, you need to set up a suitable port forward so that your PC can connect to a TCP socket opened by the Agent inside the emulator, or on the device. By default, drozer uses port 31415:

`$ adb forward tcp:31415 tcp:31415`

Now, launch the Agent, select the “Embedded Server” option and tap “Enable” to start the server. You should see a notification that the server has started.

Then, on your PC, connect using the drozer Console:

`$ drozer console connect`

If using a real device, the IP address of the device on the network must be specified:

`$ drozer console connect --server 192.168.0.10`

You should be presented with a Drozer command prompt:

```
selecting f75640f67144d9a3 (unknown sdk 4.1.1)  
dz>
```

##### Using Modules

Out of the box, Drozer provides modules to investigate various aspects of the Android platform, and a few
remote exploits. You can extend Drozer's functionality by downloading and installing additional modules.

###### Finding Modules

The official Drozer module repository is hosted alongside the main project on Github. This is automatically set
up in your copy of Drozer. You can search for modules using the `module` command:

```bash
dz> module search tool
kernelerror.tools.misc.installcert
metall0id.tools.setup.nmap
mwrlabs.tools.setup.sqlite3
```

For more information about a module, pass the `–d` option to view the module's description:

```
dz> module  search url -d
mwrlabs.urls
    Finds URLs with the HTTP or HTTPS schemes by searching the strings
    inside APK files.

        You can, for instance, use this for finding API servers, C&C
    servers within malicious APKs and checking for presence of advertising
    networks.

```

###### Installing Modules

You can install modules using the `module` command:

```
dz> module install mwrlabs.tools.setup.sqlite3
Processing mwrlabs.tools.setup.sqlite3... Already Installed.
Successfully installed 1 modules, 0 already installed
```

This will install any module that matches your query. Newly installed modules are dynamically loaded into the
console and are available for immediate use.

#### Firebase/Google Cloud Messaging (FCM/GCM)

Firebase Cloud Messaging (FCM) is the successor of Google Cloud Messaging (GCM) and is a free service offered by Google and allows to send messages between an application server and client apps. The server and client app are communicating via the FCM/GCM connection server that is handling the downstream and upstream messages.

![Architectural Overview](Images/Chapters/0x05b/FCM-notifications-overview.png)

Downstream messages are sent from the application server to the client app (push notifications); upstream messages are sent from the client app to the server.

FCM is available for Android and also for iOS and Chrome. FCM provides two connection server protocols at the moment: HTTP and XMPP and there are several differences in the implementation, as described in the official documentation<sup>[24]</sup>. The following example demonstrates how to intercept both protocols.

##### Preparation

For a full dynamic analysis of an Android app FCM should be intercepted. To be able to intercept the messages several steps should be considered for preparation.

* Install the CA certificate of your interception proxy into your Android phone<sup>[2]</sup>.
* A Man-in-the-middle attack should be executed so all traffic from the mobile device is redirected to your testing machine. This can be done by using a tool like ettercap<sup>[24]</sup>. It can be installed by using brew on Mac OS X.

```bash
$ brew install ettercap
```

Ettercap can also be installed through `apt-get` on Debian based linux distributions.

```bash
sudo apt-get install zlib1g zlib1g-dev
sudo apt-get install build-essential
sudo apt-get install ettercap
```

FCM can use two different protocols to communicate with the Google backend, either XMPP or HTTP.

**HTTP**

The ports used by FCM for HTTP are 5228, 5229, and 5230. Typically only 5228 is used, but sometimes also 5229 or 5230 is used.

* Configure a local port forwarding on your machine for the ports used by FCM. The following example can be used on Mac OS X<sup>[23]</sup>:

```bash
$ echo "
rdr pass inet proto tcp from any to any port 5228-> 127.0.0.1 port 8080
rdr pass inet proto tcp from any to any port 5229 -> 127.0.0.1 port 8080
rdr pass inet proto tcp from any to any port 5239 -> 127.0.0.1 port 8080
" | sudo pfctl -ef -
```

* The interception proxy need to listen to the port specified in the port forwarding rule above, which is 8080.

**XMPP**

The ports used by FCM over XMPP are 5235 (Production) and 5236 (Testing)<sup>[26]</sup>.

* Configure a local port forwarding on your machine for the ports used by FCM. The following example can be used on Mac OS X<sup>[23]</sup>:

```bash
$ echo "
rdr pass inet proto tcp from any to any port 5235-> 127.0.0.1 port 8080
rdr pass inet proto tcp from any to any port 5236 -> 127.0.0.1 port 8080
" | sudo pfctl -ef -
```

* The interception proxy need to listen to the port specified in the port forwarding rule above, which is 8080.

##### Intercepting Messages

Your testing machine and the Android device need to be in the same wireless network. Start ettercap with the following command and replace the IP addresses with the one of the Android device and the network gateway in the wireless network.

```bash
$ ettercap -T -i eth0 -M arp:remote /192.168.0.1// /192.168.0.105//
```

Start using the app and trigger a function that uses FCM. You should see HTTP messages showing up in your interception proxy.

![Intercepted Messages](Images/Chapters/0x05b/FCM_Intercept.png)

Interception proxies like Burp or OWASP ZAP will not show this traffic, as they are not capable of decoding it properly by default. There are two plugins available for Burp, which are Burp-non-HTTP-Extension<sup>[28]<sup> and Mitm-relay<sup>[27]<sup> that leverages Burp to visualize XMPP traffic.

As an alternative to a Mitm attack executed on your machine, a Wifi Access Point (AP) or router can also be used instead. The setup would become a little bit more complicated, as port forwarding needs to be configured on the AP or router and need to point to your interception proxy that need to listen on the external interface of your machine. For this test setup tools like ettercap are not needed anymore.

Tools like Wireshark can be used to monitor and record the traffic for further investigation either locally on your machine or through a span port, if the router or Wifi AP offers this functionality.


#### Reverse Engineering

There are many reason to reverse engineer an application: to understand application security logic, to identify application secrets and so on. More details on reverse engineering Android applications are covered in the next chapter [Tampering and Reverse Engineering on Android](0x05b-Reverse-Engineering-and-Tampering.md).


### References

- [1] Configuring an Android Device to Work With Burp - https://support.portswigger.net/customer/portal/articles/1841101-Mobile%20Set-up_Android%20Device.html
- [2] Installing Burp's CA Certificate in an Android Device - https://support.portswigger.net/customer/portal/articles/1841102-installing-burp-s-ca-certificate-in-an-android-device
- [3] Creating an Ad-hoc Wireless Network in OS X - https://support.portswigger.net/customer/portal/articles/1841150-Mobile%20Set-up_Ad-hoc%20network_OSX.html
- [4] Android Application Security Testing Guide: Part 2 - http://resources.infosecinstitute.com/android-app-sec-test-guide-part-2/#gref
- [5] Create and Manage Virtual Devices - https://developer.android.com/studio/run/managing-avds.html
- [6] GPS Emulation - https://developer.android.com/studio/run/emulator-commandline.html#geo
- [7] SMS Emulation - https://developer.android.com/studio/run/emulator-commandline.html#sms
- [8] Mobile Security Certificate Pinning -  http://blog.dewhurstsecurity.com/2015/11/10/mobile-security-certificate-pining.html
- [9] Frida - https://www.frida.re/docs/android/
- [10] ADBI - https://github.com/crmulliner/adbi
- [11] SSLUnpinning - https://github.com/ac-pm/SSLUnpinning_Xposed
- [12] Android-SSL-TrustKiller - https://github.com/iSECPartners/Android-SSL-TrustKiller
- [13] Defeating SSL Pinning in Coin's Android Application -  http://rotlogix.com/2015/09/13/defeating-ssl-pinning-in-coin-for-android/
- [14] RootBeet - https://github.com/scottyab/rootbeer
- [15] Android Lint - https://sites.google.com/a/android.com/tools/tips/lint/
- [16] devknox - https://devknox.io/
- [17] Android application package - https://en.wikipedia.org/wiki/Android_application_package
- [18] QARK - https://github.com/linkedin/qark/
- [19] Androbugs - https://github.com/AndroBugs/AndroBugs_Framework
- [20] JAADAS - https://github.com/flankerhqd/JAADAS
- [21] Guide to root mobile devices - https://www.xda-developers.com/root/
- [22] Bypassing SSL Pinning in Android Applications - https://serializethoughts.com/2016/08/18/bypassing-ssl-pinning-in-android-applications/
- [23] Mac OS X Port Forwarding - https://salferrarello.com/mac-pfctl-port-forwarding/
- [23] Ettercap - https://ettercap.github.io
- [24] Differences of HTTP and XMPP in FCM: https://firebase.google.com/docs/cloud-messaging/server#choose
- [25] Drozer - https://github.com/mwrlabs/drozer
- [26] Firebase via XMPP - https://firebase.google.com/docs/cloud-messaging/xmpp-server-ref
- [27] Mitm-relay - https://github.com/jrmdev/mitm_relay
- [28] Burp-non-HTTP-Extension - https://github.com/summitt/Burp-Non-HTTP-Extension
