# モバイルアプリのネットワーク通信

ネットワークに接続されたすべてのモバイルアプリは Hypertext Transfer Protocol (HTTP) または HTTP over Transport Layer Security (TLS), HTTPS を使用してリモートエンドポイントとの間でデータを送受信します。その結果、ネットワークベースの攻撃 (パケットスニッフィングや中間者攻撃など) が問題になります。この章ではモバイルアプリとエンドポイント間のネットワーク通信に関する潜在的な脆弱性、テスト技法、ベストプラクティスについて説明します。

## HTTP(S) トラフィックの傍受

多くの場合、HTTP(S) トラフィックがホストコンピュータ上で実行されている _傍受プロキシ_ 経由でリダイレクトされるように、モバイルデバイス上にシステムプロキシを設定することが最も実用的です。モバイルアプリクライアントとバックエンドの間のリクエストを監視することにより、利用可能なサーバーサイド API を簡単にマップし、通信プロトコルの情報を得ることができます。さらに、サーバー側の脆弱性をテストするためにリクエストを再生および操作できます。

フリーおよび商用のプロキシツールがいくつかあります。最も人気のあるものは以下のとおりです。

- [Burp Suite](0x08-Testing-Tools.md#burp-suite)
- [OWASP ZAP](0x08-Testing-Tools.md#owasp-zap)

傍受プロキシを使用するには、それをホストコンピュータ上で実行し、HTTP(S) リクエストをプロキシにルーティングするようモバイルアプリを設定する必要があります。ほとんどの場合、モバイルデバイスのネットワーク設定でシステム全体のプロキシを設定するだけで十分です。アプリが標準の HTTP API や `okhttp` などの一般的なライブラリを使用する場合、自動的にシステム設定を使用します。

<img src="Images/Chapters/0x04f/BURP.png" width="100%" />

プロキシを使用すると SSL 証明書の検証が中断され、アプリは通常 TLS 接続を開始できません。この問題を回避するには、プロキシの CA 証明書をデバイスにインストールします。OS ごとの「テスト環境構築」の章でこれを行う方法について説明します。

## 非 HTTP トラフィックを処理するための Burp プラグイン

Burp や OWASP ZAP などの傍受プロキシは非 HTTP トラフィックを表示しません。デフォルトでは正しくデコードできないためです。しかしながら、以下のような Burp プラグインを利用できます。

- [Burp-non-HTTP-Extension](https://github.com/summitt/Burp-Non-HTTP-Extension "Burp-non-HTTP-Extension")
- [Mitm-relay](https://github.com/jrmdev/mitm_relay "Mitm-relay")

これらのプラグインは非 HTTP プロトコルを視覚化することができ、トラフィックを傍受および操作することもできます。

このセットアップは非常に面倒になることがあり、HTTP をテストするほど簡単ではないことに注意します。

## ネットワーク層でのトラフィックの傍受

傍受プロキシを使用することによる動的解析は、標準ライブラリがアプリで使用され、すべての通信が HTTP 経由で行われる場合には簡単です。しかしこれが動作しないいくつかのケースがあります。

- システムプロキシ設定を無視する [Xamarin](https://www.xamarin.com/platform "Xamarin") などのモバイルアプリケーション開発プラットフォームが使用されている場合。
- モバイルアプリケーションがシステムプロキシが使用されているかどうかを確認し、プロキシを介してリクエストを送信することを拒否する場合。
- Android の GCM/FCM などのプッシュ通信を傍受したい場合。
- XMPP や他の非 HTTP プロトコルが使用されている場合。

このような場合は、次に何をすべきかを決めるために、まずネットワークトラフィックを監視および解析する必要があります。幸いにも、ネットワーク通信をリダイレクトおよび傍受するための選択肢がいくつかあります。

- トラフィックをホストコンピュータにルーティングします。ホストコンピュータをネットワークゲートウェイとして設定します。例えば、オペレーティングシステムに内蔵のインターネット共有機能を使用します。それから、[Wireshark](0x08-Testing-Tools.md#wireshark) を使用して、モバイルデバイスからの任意のトラフィックを傍受できます。
- 場合によっては MITM 攻撃を実行してモバイルデバイスに強制的に会話させる必要があります。このシナリオではモバイルデバイスからホストコンピュータにネットワークトラフィックをリダイレクトするために [bettercap](0x08-Testing-Tools.md#bettercap) または独自のアクセスポイントを検討する必要があります (下図参照) 。
- ルート化デバイスでは、フックやコードインジェクションを使用して、ネットワーク関連の API コール (HTTP リクエストなど) を傍受したり、これらのコールの引数をダンプしたり操作することも可能です。これにより実際のネットワークデータを検査する必要がなくなります。これらの技法については「リバースエンジニアリングと改竄」の章で詳しく説明します。
- macOS では、iOS デバイスのすべてのトラフィックを傍受するために "Remote Virtual Interface" を作成できます。「iOS アプリのテスト環境構築」の章でこの手法を説明します。

### bettercap による中間者攻撃のシミュレーション

#### ネットワークのセットアップ

中間者のポジションを得るには、モバイルフォンおよびそれと通信するゲートウェイと同じワイヤレスネットワークにホストコンピュータがある必要があります。これが完了するとモバイルフォンの IP アドレスが必要です。モバイルアプリの完全な動的解析には、すべてのネットワークトラフィックを傍受する必要があります。

### MITM 攻撃

まずお好みのネットワーク解析ツールを起動し、次に以下のコマンドで IP アドレス (X.X.X.X) を MITM 攻撃を実行したいターゲットに置き換えて [bettercap](0x08-Testing-Tools.md#bettercap) を実行します。

```bash
$ sudo bettercap -eval "set arp.spoof.targets X.X.X.X; arp.spoof on; set arp.spoof.internal true; set arp.spoof.fullduplex true;"
bettercap v2.22 (built for darwin amd64 with go1.12.1) [type 'help' for a list of commands]

[19:21:39] [sys.log] [inf] arp.spoof enabling forwarding
[19:21:39] [sys.log] [inf] arp.spoof arp spoofer started, probing 1 targets.
```

bettercap は自動的にパケットを (ワイヤレス) ネットワークのネットワークゲートウェイに送信します。あなたはそのトラフィックを盗聴できます。2019年の初めに [全二重 ARP スプーフィング](https://github.com/bettercap/bettercap/issues/426 "Full Duplex ARP Spoofing") サポートが bettercap に追加されました。

モバイルフォンでブラウザを起動して `http://example.com` に移動すると、Wireshark を使用している場合には以下のような出力が表示されるはずです。

<img src="Images/Chapters/0x04f/bettercap.png" width="100%" />

それで、モバイルフォンで送受信される完全なネットワークトラフィックを確認できるようになります。これには DNS, DHCP およびその他の形式の通信も含まれるため、非常に「ノイズが多い」かもしれません。したがって、関連するトラフィックだけに集中するために、[Wireshark の DisplayFilter](https://wiki.wireshark.org/DisplayFilters "DisplayFilters") の使い方や [tcpdump でフィルタする方法](https://danielmiessler.com/study/tcpdump/#gs.OVQjKbk "A tcpdump Tutorial and Primer with Examples") を知る必要があります。

> 中間者攻撃は ARP スプーフィングを通じて OSI レイヤ 2 上で攻撃が実行されるため、あらゆるデバイスやオペレーティングシステムに対して機能します。あなたが MITM である場合、通過するデータは TLS を使用して暗号化されている可能性があるため、平文データを見ることができないかもしれません。しかし、それは関与するホスト、使用されるプロトコルおよびアプリが通信しているポートに関する貴重な情報をあなたに提供します。

### アクセスポイントを使用した中間者攻撃のシミュレーション

#### ネットワークのセットアップ

中間者 (MITM) 攻撃をシミュレートする簡単な方法は、スコープ内のデバイスとターゲットネットワーク間のすべてのパケットがホストコンピュータを通過するネットワークを構成することです。モバイルペネトレーションテストでは、モバイルデバイスとホストコンピュータが接続されているアクセスポイントを使用して実現できます。そうしてホストコンピュータがルータおよびアクセスポイントになります。

以下のシナリオが可能です。

- ホストコンピュータの内蔵 WiFi カードをアクセスポイントとして使用し、有線接続を使用してターゲットネットワークに接続します。
- 外部 USB WiFi カードをアクセスポイントとして使用し、ホストコンピュータの内蔵 WiFi を使用してターゲットネットワークに接続します (逆も可能です) 。
- 別のアクセスポイントを使用し、トラフィックをホストコンピュータにリダイレクトします。

外部 WiFi カードを使用するシナリオではカードがアクセスポイントを作成する機能が必要です。さらに、いくつかのツールをインストールするかネットワークを構成して中間者ポジションとなる必要があります (下記参照) 。Kali Linux で `iwconfig` コマンドを使用して、WiFi カードに AP 機能があるかどうかを確認できます。

```bash
iw list | grep AP
```

別のアクセスポイントを使用するシナリオでは AP の構成にアクセスする必要があります。AP が以下のいずれかをサポートしているかどうかを最初に確認する必要があります。

- ポートフォワーディングまたは
- スパンまたはミラーポートを持っている。

どちらの場合もホストコンピュータの IP を指すように AP を構成する必要があります。ホストコンピュータは (有線接続または WiFi を介して) AP に接続する必要があり、ターゲットネットワークに接続する必要があります (AP と同じ接続でもかまいません) 。ターゲットネットワークにトラフィックをルーティングするにはホストコンピュータに追加の構成が必要になる場合があります。

> 別のアクセスポイントがお客様のものである場合、変更を行う前に、すべての変更と構成をエンゲージメントの前に明確にし、バックアップを作成する必要があります。

<img src="Images/Chapters/0x04f/architecture_MITM_AP.png" width="100%" />

#### インストール

以下の手順はアクセスポイントと追加のネットワークインタフェースを使用して中間者ポジションをセットアップしています。

別のアクセスポイント、外部 USB WiFi カード、またはホストコンピュータの内蔵カードのいずれかを使用して WiFi ネットワークを作成します。

これは macOS のビルトインユーティリティを使用して実行できます。[Mac のインターネット接続を他のネットワークユーザーと共有する](https://support.apple.com/en-ke/guide/mac-help/mchlp1540/mac "Share the internet connection on Mac with other network users") を使用できます。

すべての主要な Linux および Unix オペレーティングシステムでは以下のようなツールが必要です。

- hostapd
- dnsmasq
- iptables
- wpa_supplicant
- airmon-ng

Kali Linux ではこれらのツールを `apt-get` でインストールできます。

```bash
apt-get update
apt-get install hostapd dnsmasq aircrack-ng
```

> iptables と wpa_supplicant は Kali Linux にデフォルトでインストールされています。

別のアクセスポイントの場合、トラフィックをホストコンピュータにルーティングします。外部 USB WiFi カードまたは内蔵 WiFi カードの場合、トラフィックはすでにホストコンピュータで利用可能です。

WiFi からの着信トラフィックを、トラフィックがターゲットネットワークに到達できる追加のネットワークインタフェースにルーティングします。追加のネットワークインタフェースは、セットアップに応じて有線接続または他の WiFi カードにできます。

#### 構成

Kali Linux の構成ファイルにフォーカスします。以下の値を定義する必要があります。

- wlan1 - AP ネットワークインタフェースの ID (AP 機能あり)
- wlan0 - ターゲットネットワークインタフェースの ID (これは有線インタフェースまたは他の WiFi カードにできます)
- 10.0.0.0/24 - AP ネットワークの IP アドレスとマスク

以下の構成ファイルを変更し適宜に調整する必要があります。

- hostapd.conf

    ```bash
    # Name of the WiFi interface we use
    interface=wlan1
    # Use the nl80211 driver
    driver=nl80211
    hw_mode=g
    channel=6
    wmm_enabled=1
    macaddr_acl=0
    auth_algs=1
    ignore_broadcast_ssid=0
    wpa=2
    wpa_key_mgmt=WPA-PSK
    rsn_pairwise=CCMP
    # Name of the AP network
    ssid=STM-AP
    # Password of the AP network
    wpa_passphrase=password
    ```

- wpa_supplicant.conf

    ```bash
    network={
        ssid="NAME_OF_THE_TARGET_NETWORK"
        psk="PASSWORD_OF_THE_TARGET_NETWORK"
    }
    ```

- dnsmasq.conf

    ```bash
    interface=wlan1
    dhcp-range=10.0.0.10,10.0.0.250,12h
    dhcp-option=3,10.0.0.1
    dhcp-option=6,10.0.0.1
    server=8.8.8.8
    log-queries
    log-dhcp
    listen-address=127.0.0.1
    ```

#### MITM 攻撃

中間者ポジションを取得できるためには上記の構成を実行する必要があります。これは Kali Linux 上で以下のコマンドを使用して実行できます。

```bash
# check if other process is not using WiFi interfaces
$ airmon-ng check kill
# configure IP address of the AP network interface
$ ifconfig wlan1 10.0.0.1 up
# start access point
$ hostapd hostapd.conf
# connect the target network interface
$ wpa_supplicant -B -i wlan0 -c wpa_supplicant.conf
# run DNS server
$ dnsmasq -C dnsmasq.conf -d
# enable routing
$ echo 1 > /proc/sys/net/ipv4/ip_forward
# iptables will NAT connections from AP network interface to the target network interface
$ iptables --flush
$ iptables --table nat --append POSTROUTING --out-interface wlan0 -j MASQUERADE
$ iptables --append FORWARD --in-interface wlan1 -j ACCEPT
$ iptables -t nat -A POSTROUTING -j MASQUERADE
```

これでモバイルデバイスをアクセスポイントに接続できます。

### ネットワーク解析ツール

ホストコンピュータにリダイレクトされるネットワークトラフィックを監視および解析できるツールをインストールします。もっとも一般的な二つのネットワーク監視 (またはキャプチャ) ツールは以下の通りです。

- [Wireshark](https://www.wireshark.org "Wireshark") (CLI pendant: [TShark](https://www.wireshark.org/docs/man-pages/tshark.html "TShark"))
- [tcpdump](https://www.tcpdump.org/tcpdump_man.html "tcpdump")

Wireshark には GUI があり、コマンドラインに慣れていないのであれば簡単です。コマンドラインツールを探しているのであれば TShark または tcpdump を使用する必要があります。これらのツールはいずれも、すべての主要な Linux および Unix オペレーティングシステムで利用可能であり、それぞれのパッケージインストールメカニズムの一部です。

### 実行時計装によるプロキシの設定

ルート化または脱獄済みデバイスでは、ランタイムフックを使用して、新しいプロキシを設定したりネットワークトラフィックをリダイレクトすることが可能です。これは [Inspeckage](https://github.com/ac-pm/Inspeckage "Inspeckage") などのフックツールや [Frida](https://www.frida.re "Frida") および [cycript](http://www.cycript.org "cycript") などのコードインジェクションフレームワークで実現できます。実行時計装についての詳細はこのガイドの「リバースエンジニアリングと改竄」の章で参照できます。

### 例 - Xamarin の扱い

例として、すべてのリクエストを Xamarin アプリから傍受プロキシにリダイレクトしてみます。

Xamarin は Visual Studio と C# をプログラミング言語として使用して [ネイティブ Android](https://docs.microsoft.com/en-us/xamarin/android/get-started/ "Getting Started with Android") および [iOS アプリ](https://docs.microsoft.com/en-us/xamarin/ios/get-started/ "Getting Started with iOS") を作成できるモバイルアプリケーション開発プラットフォームです。

Xamarin アプリをテストするときに Wi-Fi 設定でシステムプロキシを設定しようとすると、傍受プロキシで HTTP リクエストを見ることができなくなります。Xamarin により作成されたアプリはスマホのローカルプロキシ設定を使用しないためです。これを解決する方法は三つあります。

- 第一の方法: [アプリにデフォルトプロキシ](https://developer.xamarin.com/api/type/System.Net.WebProxy/ "System.Net.WebProxy Class") を追加します。`OnCreate` または `Main` に以下のコードを追加してアプリを再作成します。

    ```cs
    WebRequest.DefaultWebProxy = new WebProxy("192.168.11.1", 8080);
    ```

- 第二の方法: bettercap を使用して中間者ポジション (MITM) を取得します。MITM 攻撃のセットアップ方法については上記のセクションを参照してください。MITM であれば、ポート 443 を localhost 上で動作する傍受プロキシにリダイレクトするだけです。これは macOS で `rdr` コマンドを使うことにより行えます。

    ```bash
    $ echo "
    rdr pass inet proto tcp from any to any port 443 -> 127.0.0.1 port 8080
    " | sudo pfctl -ef -
    ```

- Linux システムでは `iptables` を使用できます。

    ```bash
    sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 127.0.0.1:8080
    ```

- 最後のステップとして、 Burp Suite の listener settings で 'Support invisible proxy' をセットする必要があります。

- 第三の方法: bettercap の代わりのものでモバイルフォンの `/etc/hosts` を調整します。 `/etc/hosts` にターゲットドメインのエントリを追加し、傍受プロキシの IP アドレスをポイントします。これにより bettercap と同様に MiTM となる状況を生成します。傍受プロキシで使用されるポートにポート 443 をリダイレクトする必要があります。リダイレクトは上述のように適用できます。さらに、トラフィックを傍受プロキシから元のロケーションとポートにリダイレクトする必要があります。

> トラフィックをリダイレクトする際、ノイズとスコープ外のトラフィックを最小限に抑えるために、スコープ内のドメインと IP を狭めるルールを作成する必要があります。

傍受プロキシは上記のポートフォワーディングルールで指定されたポート 8080 をリッスンする必要があります。

Xamarin アプリがプロキシを使用 (例えば `WebRequest.DefaultWebProxy` を使用) するように設定されている場合、トラフィックを傍受プロキシにリダイレクトした後、次にトラフィックを送信すべき場所を指定する必要があります。そのトラフィックを元のロケーションにリダイレクトする必要があります。以下の手順は Burp で元のロケーションへのリダイレクトを設定しています。

1. **Proxy** タブに移動し、**Options** をクリックします。
2. proxy listeners のリストからリスナーを選択して編集します。
3. **Request handling** タブに移動して以下をセットします。

    - Redirect to host: 元のトラフィックロケーションを指定します。
    - Redirect to port: 元のポートロケーションを指定します。
    - 'Force use of SSL' をセット (HTTPS 使用時) および 'Support invisible proxy' をセットします。

<img src="Images/Chapters/0x04f/burp_xamarin.png" width="100%" />

<br/>
<br/>

#### CA 証明書

まだ行われていなければ、HTTPS リクエストの傍受を許可するモバイルデバイスに CA 証明書をインストールします。

- [Android フォンに傍受プロキシの CA 証明書をインストールする](https://support.portswigger.net/customer/portal/articles/1841102-installing-burp-s-ca-certificate-in-an-android-device "Installing Burp\'s CA Certificate in an Android Device")
    > Android 7.0 (API level 24) 以降、アプリで指定されていない限り、OS はもはやユーザー指定の CA 証明書を信頼しないことに注意します。このセキュリティ対策の回避については、「セキュリティテスト入門」の章で説明します。
- [iOS フォンに傍受プロキシの CA 証明書をインストールする](https://support.portswigger.net/customer/portal/articles/1841108-configuring-an-ios-device-to-work-with-burp "Configuring an iOS Device to Work With Burp")

#### トラフィックの傍受

アプリの使用を開始し、その機能を動かします。傍受プロキシに HTTP メッセージが表示されるはずです。

> bettercap を使用する場合は、Proxy タブ / Options / Edit Interface で "Support invisible proxying" を有効にする必要があります

## ネットワーク上のデータ暗号化の検証 (MSTG-NETWORK-1 および MSTG-NETWORK-2)

### 概要

コアとなるモバイルアプリの機能のひとつはインターネットなどの信頼できないネットワーク上でデータを送受信することです。データが転送中に正しく保護されない場合、ネットワークインフラストラクチャの任意の部分 (Wi-Fi アクセスポイントなど) にアクセスできる攻撃者は、傍受、読み取り、改変の可能性があります。これが平文のネットワークプロトコルがほとんど推奨されない理由です。

大部分のアプリはバックエンドとの通信に HTTP に依存しています。HTTPS は暗号化された接続で HTTP をラップします (略語の HTTPS はもともと HTTP over Secure Socket Layer (SSL) と呼ばれていました。SSL は TLS の前身で非推奨です) 。TLS はバックエンドサービスの認証を可能にし、ネットワークデータの機密性と完全性を保証します。

#### 推奨される TLS 設定

サーバー側で適切な TLS 設定を確保することも重要です。SSL プロトコルは非推奨であり、もはや使用すべきではありません。
また TLS v1.0 および TLS v1.1 には [既知の脆弱性](https://portswigger.net/daily-swig/the-end-is-nigh-browser-makers-ditch-support-for-aging-tls-1-0-1-1-protocols "Browser-makers ditch support for aging TLS 1.0, 1.1 protocols") があり、2020年までにすべての主要なブラウザでその使用が非推奨になりました。
TLS v1.2 および TLS v1.3 はデータのセキュアな送信のためのベストプラクティスとみなされています。Android 10 (API level 29) 以降 TLS v1.3 はより高速でセキュアな通信のためにデフォルトで有効になります。[TLS v1.3 での主な変更点](https://developer.android.com/about/versions/10/behavior-changes-all#tls-1.3 "TLS 1.3 enabled by default") は暗号スイートのカスタマイズができなくなること、および TLS v1.3 が有効である場合にはそれらすべてが有効になることです。一方、ゼロラウンドトリップ (0-RTT) モードはサポートされません。

クライアントとサーバーの両方が同じ組織により制御され、互いに通信するためだけに使用される場合、[設定を堅牢にすること](https://dev.ssllabs.com/projects/best-practices/ "Qualys SSL/TLS Deployment Best Practices") によりセキュリティを向上できます。

モバイルアプリケーションが特定のサーバーに接続している場合、そのネットワークスタックを調整して、サーバーの構成に対して可能な限り高いセキュリティレベルを確保できます。基盤となるオペレーティングシステムのサポートがない場合、モバイルアプリケーションがより脆弱な構成を使用するように強制する可能性があります。

##### 暗号スイートの用語

暗号スイートの構造は以下の通りです。

- **プロトコル_鍵交換アルゴリズム_WITH_ブロック暗号_完全性チェックアルゴリズム**

この構造を以下で説明します。

- プロトコル: 暗号が使用するプロトコル
- 鍵交換アルゴリズム: TLS ハンドシェイク時の認証にサーバーおよびクライアントで使用される鍵交換アルゴリズム
- グロック暗号: メッセージストリームを暗号化するために使用されるブロック暗号
- 完全性チェックアルゴリズム: メッセージを認証するために使用される完全性チェックアルゴリズム

例: `TLS_RSA_WITH_3DES_EDE_CBC_SHA`

上記の例では暗号スイートは以下のものを使用します。

- TLS をプロトコルとして
- RSA を認証用の非対称暗号に
- 3DES を EDE_CBC モードで対称暗号用に
- SHA を完全性用のハッシュアルゴリズムに

TLSv1.3 では鍵交換アルゴリズムは暗号スイートの一部ではなく、代わりに TLS ハンドシェイク時に決定されることに注意します。

以下のリストでは、暗号スイートの各部分のさまざまなアルゴリズムについて説明します。

プロトコル:

- `SSLv1`
- `SSLv2` - [RFC 6176](https://tools.ietf.org/html/rfc6176 "RFC 6176")
- `SSLv3` - [RFC 6101](https://tools.ietf.org/html/rfc6101 "RFC 6101")
- `TLSv1.0` - [RFC 2246](https://www.ietf.org/rfc/rfc2246 "RFC 2246")
- `TLSv1.1` - [RFC 4346](https://tools.ietf.org/html/rfc4346 "RFC 4346")
- `TLSv1.2` - [RFC 5246](https://tools.ietf.org/html/rfc5246 "RFC 5246")
- `TLSv1.3` - [RFC 8446](https://tools.ietf.org/html/rfc8446 "RFC 8446")

鍵交換アルゴリズム:

- `DSA` - [RFC 6979](https://tools.ietf.org/html/rfc6979 "RFC 6979")
- `ECDSA` - [RFC 6979](https://tools.ietf.org/html/rfc6979 "RFC 6979")
- `RSA` - [RFC 8017](https://tools.ietf.org/html/rfc8017 "RFC 8017")
- `DHE` - [RFC 2631](https://tools.ietf.org/html/rfc2631 "RFC 2631")  - [RFC 7919](https://tools.ietf.org/html/rfc7919 "RFC 7919")
- `ECDHE` - [RFC 4492](https://tools.ietf.org/html/rfc4492 "RFC 4492")
- `PSK` - [RFC 4279](https://tools.ietf.org/html/rfc4279 "RFC 4279")
- `DSS` - [FIPS186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf "FIPS186-4")
- `DH_anon` - [RFC 2631](https://tools.ietf.org/html/rfc2631 "RFC 2631")  - [RFC 7919](https://tools.ietf.org/html/rfc7919 "RFC 7919")
- `DHE_RSA` - [RFC 2631](https://tools.ietf.org/html/rfc2631 "RFC 2631")  - [RFC 7919](https://tools.ietf.org/html/rfc7919 "RFC 7919")
- `DHE_DSS` - [RFC 2631](https://tools.ietf.org/html/rfc2631 "RFC 2631")  - [RFC 7919](https://tools.ietf.org/html/rfc7919 "RFC 7919")
- `ECDHE_ECDSA` - [RFC 8422](https://tools.ietf.org/html/rfc8422 "RFC 8422")
- `ECDHE_PSK`  - [RFC 8422](https://tools.ietf.org/html/rfc8422 "RFC 8422")  - [RFC 5489](https://tools.ietf.org/html/rfc5489 "RFC 5489")
- `ECDHE_RSA`  - [RFC 8422](https://tools.ietf.org/html/rfc8422 "RFC 8422")

ブロック暗号:

- `DES`  - [RFC 4772](https://tools.ietf.org/html/rfc4772 "RFC 4772")
- `DES_CBC`  - [RFC 1829](https://tools.ietf.org/html/rfc1829 "RFC 1829")
- `3DES`  - [RFC 2420](https://tools.ietf.org/html/rfc2420 "RFC 2420")
- `3DES_EDE_CBC` - [RFC 2420](https://tools.ietf.org/html/rfc2420 "RFC 2420")
- `AES_128_CBC` - [RFC 3268](https://tools.ietf.org/html/rfc3268 "RFC 3268")
- `AES_128_GCM`  - [RFC 5288](https://tools.ietf.org/html/rfc5288 "RFC 5288")
- `AES_256_CBC` - [RFC 3268](https://tools.ietf.org/html/rfc3268 "RFC 3268")
- `AES_256_GCM` - [RFC 5288](https://tools.ietf.org/html/rfc5288 "RFC 5288")
- `RC4_40`  - [RFC 7465](https://tools.ietf.org/html/rfc7465 "RFC 7465")
- `RC4_128`  - [RFC 7465](https://tools.ietf.org/html/rfc7465 "RFC 7465")
- `CHACHA20_POLY1305`  - [RFC 7905](https://tools.ietf.org/html/rfc7905 "RFC 7905")  - [RFC 7539](https://tools.ietf.org/html/rfc7539 "RFC 7539")

完全性チェックアルゴリズム:

- `MD5`  - [RFC 6151](https://tools.ietf.org/html/rfc6151 "RFC 6151")
- `SHA`  - [RFC 6234](https://tools.ietf.org/html/rfc6234 "RFC 6234")
- `SHA256`  - [RFC 6234](https://tools.ietf.org/html/rfc6234 "RFC 6234")
- `SHA384`  - [RFC 6234](https://tools.ietf.org/html/rfc6234 "RFC 6234")

暗号スイートの性能はそのアルゴリズムの性能に依存することに注意します。

以下では、TLS で使用する最新の推奨暗号スイートリストを提示します。これらの暗号スイートは IANA の TLS パラメータドキュメントと OWASP TLS Cipher String Cheat Sheet の両方で推奨されています。

- IANA 推奨暗号スイートは [TLS Cipher Suites](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4 "TLS Cipher Suites") にあります。
- OWASP 推奨暗号スイートは [TLS Cipher String Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/TLS_Cipher_String_Cheat_Sheet.md "OWASP TLS Cipher String Cheat Sheet") にあります。

Android 10 では以下の [SHA-2 CBC 暗号スイートが削除された](https://developer.android.com/about/versions/10/behavior-changes-all#sha2-cbc-cipher-suites "SHA-2 CBC cipher suites removed") ことに注意します。

- `TLS_RSA_WITH_AES_128_CBC_SHA256`
- `TLS_RSA_WITH_AES_256_CBC_SHA256`
- `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256`
- `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384`
- `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256`
- `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384`

一部の Android および iOS バージョンは推奨暗号スイートの一部をサポートしていないため、互換性を保つために [Android](https://developer.android.com/reference/javax/net/ssl/SSLSocket#cipher-suites "Cipher suites") および [iOS](https://developer.apple.com/documentation/security/1550981-ssl_cipher_suite_values?language=objc "SSL Cipher Suite Values") バージョンでサポートされている暗号スイートを確認し、サポートされている上位の暗号スイートを選択します。

### 静的解析

最初に、ソースコード内のすべてのネットワークリクエストを特定し、プレーンの HTTP URL が使用されていないことを確認します。機密情報は [`HttpsURLConnection`](https://developer.android.com/reference/javax/net/ssl/HttpsURLConnection.html "HttpsURLConnection") や [`SSLSocket`](https://developer.android.com/reference/javax/net/ssl/SSLSocket.html "SSLSocket") (TLS を使用したソケットレベル通信用) を使用することによりセキュアなチャネルを介して送信されていることを確認します。

次に、アプリがクリアテキスト HTTP トラフィックを許可していないことを確認する必要があります。Android 9 (API レベル 28) 以降、クリアテキスト HTTP トラフィックはデフォルトでブロックされますが、アプリケーションがそれを送信する方法は複数存在します。

- AndroidManifest.xml ファイルの `<application>` タグの [`android:usesCleartextTraffic`](https://developer.android.com/guide/topics/manifest/application-element#usesCleartextTraffic "Android documentation - usesCleartextTraffic flag") 属性を設定します。なお [Network Security Configuration](https://developer.android.com/training/articles/security-config.html) が構成されている場合には、このフラグは無視されます。
- Network Security Configuration を構成して、`<domain-config>` 要素の `cleartextTrafficPermitted` 属性を true に設定し、クリアテキストトラフィックを有効にします。
- 低レベル API ([`Socket`](https://developer.android.com/reference/java/net/Socket "Socket class") など) を使用して、カスタム HTTP 接続を設定します。
- クロスプラットフォームフレームワーク (Flutter, Xamarin など) を使用します。これらは一般的に HTTP ライブラリ実装を独自に備えています。

上記のすべてのケースは全体として注意深く分析する必要があります。例えば、アプリが Android Manifest や Network Security Configuration でクリアテキストトラフィックを許可していなくても、実際には HTTP トラフィックを送信している可能性があります。低レベル API を使用している (Network Security Configuration は無視される) 場合やクロスプラットフォームフレームワークが適切に設定されていない場合に当てはまります。

次に、セキュアな接続を確立することを前提とした低レベル API (`SSLSocket` など) を使用する場合でも、セキュアに実装する必要があることに注意します。例えば、`SSLSocket` はホスト名を検証 **しません** 。ホスト名の検証には `getDefaultHostnameVerifier` を使用します。Android 開発者ドキュメントに [コード例](https://developer.android.com/training/articles/security-ssl.html#WarningsSslSocket "Warnings About Using SSLSocket Directly") があります。

最後に、HTTPS 接続の終端となるサーバーや終端プロキシがベストプラクティスに従って構成されていることを検証します。[OWASP Transport Layer Protection チートシート](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.md "Transport Layer Protection Cheat Sheet") および [Qualys SSL/TLS Deployment Best Practices](https://dev.ssllabs.com/projects/best-practices/ "Qualys SSL/TLS Deployment Best Practices") も参照してください。

### 動的解析

テストされるアプリの着信および発信するネットワークトラフィックを傍受し、このトラフィックが暗号化されていることを確認します。以下のいずれかの方法でネットワークトラフィックを傍受できます。

- [OWASP ZAP](0x08-Testing-Tools.md#owasp-zap) や [Burp Suite](0x08-Testing-Tools.md#burp-suite) などの傍受プロキシですべての HTTP(S) および Websocket トラフィックをキャプチャし、すべてにリクエストが HTTP ではなく HTTPS 経由で行われていることを確認します。
- Burp や OWASP ZAP などの傍受プロキシは HTTP(S) トラフィックのみを表示します。しかし、[Burp-non-HTTP-Extension](https://github.com/summitt/Burp-Non-HTTP-Extension "Burp-non-HTTP-Extension") などの Burp プラグインや [mitm-relay](https://github.com/jrmdev/mitm_relay "mitm-relay") ツールを使用すると、XMPP や他のプロトコルによる通信をデコードおよび視覚化できます。

> 一部のアプリケーションでは証明書ピンニングのために Burp や OWASP ZAP などのプロキシでは動作しない可能性があります。このようなシナリオでは、「カスタム証明書ストアおよび証明書ピンニングのテスト」を参照してください。

サーバーが正しい暗号スイートをサポートしているかどうかを検証したい場合、さまざまなツールを使用できます。

- nscurl - 詳細については iOS のネットワーク通信のテストを参照してください。
- [testssl.sh](https://github.com/drwetter/testssl.sh "testssl.sh") は「TLS/SSL 暗号、プロトコルのサポートおよび一部の暗号の欠陥について、任意のポート上のサーバーのサービスをチェックするフリーのコマンドラインツールです。」

## クリティカルな操作がセキュアな通信チャネルを使用することの確認 (MSTG-NETWORK-5)

### 概要

銀行業務アプリなどの機密性の高いアプリケーションでは、[OWASP MASVS](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x03-Using_the_MASVS.md "The Mobile Application Security Verification Standard") では「多層防御」検証レベルを導入しています。そのようなアプリケーションのクリティカルな操作 (ユーザー登録やアカウント回復など) は攻撃者にとって最も魅力的なターゲットです。 SMS や電子メールに頼ることなくユーザー操作を確認するための追加のチャネルなど、高度なセキュリティコントロールを実装する必要があります。

クリティカルな操作への追加要素として SMS を使用することはお勧めできません。SIM スワップ詐欺のような攻撃は多くの場合 SMS の検証を回避するために [Instagram アカウント、暗号通貨為替](https://motherboard.vice.com/en_us/article/vbqax3/hackers-sim-swapping-steal-phone-numbers-instagram-bitcoin "The SIM Hijackers") やもちろん [金融機関](https://www.fintechnews.org/sim-swapping-how-the-mobile-security-feature-can-lead-to-a-hacked-bank-account/ "SIM swapping") を攻撃するために使用されてきました。SIM スワッピングは携帯電話番号を新しい SIM カードに切り替えるために多くの通信事業者により提供されている合法的なサービスです。攻撃者が通信事業者を説得するか、携帯ショップの小売店の従業員を雇って SIM スワップを行わせると、携帯電話番号は攻撃者が所有する SIM に転送されます。この結果、攻撃者は被害者に知られることなく SMS や音声通話をすべて受信できるようになります。

[あなたの SIM カードを保護する](https://www.wired.com/story/sim-swap-attack-defend-phone/ "How to protect yourself against a SIM swap attack") にはさまざまな方法がありますが、このレベルのセキュリティ成熟度や意識の高さを通常のユーザーからは期待できず、通信事業者により強制されることもありません。

また電子メールの使用をセキュアな通信チャネルとみなすべきではありません。電子メールの暗号化は通常ではサービスプロバイダにより提供されてはいませんし、利用可能な場合でも平均的なユーザーにより使用されてはいないため、電子メールを使用する際の機密性は保証できません。なりすまし、(スピア|ダイナマイト) フィッシング、スパムは電子メールを悪用してユーザーをだますためのさらなる方法です。したがって、SMS や電子メール以外に他のセキュアな通信チャネルを検討する必要があります。

### 静的解析

コードをレビューして、クリティカルな操作を参照する部分を特定します。そのような操作に追加のチャネルを使用していることを確認します。追加の検証チャネルの例には以下があります。

- トークン (RSA トークン, YubiKey など)
- プッシュ通知 (Google Prompt など)
- 訪問またはスキャンした他のウェブサイトからのデータ (QR コードなど)
- 物理的な文字や物理的なエントリポイントからのデータ (銀行で書類に署名した後にのみ受け取るデータなど)

クリティカルな操作ではユーザーの操作を確認するために少なくとも一つの追加チャネルの使用を強制することを確認します。クリティカルな操作を実行する際にこれらのチャネルがバイパスされてはいけません。ユーザーの身元を検証するための追加要素を実装する場合には、[Google Authenticator](https://github.com/google/google-authenticator-android "Google Authenticator for Android") を介したワンタイムパスコード (OTP) も検討してください。

### 動的解析

テストされるアプリケーションのクリティカルな操作 (ユーザー登録、アカウント回復、金融取引など) をすべて特定します。それぞれのクリティカルな操作に少なくとも一つの追加チャネルが必要であることを確認します。関数を直接呼び出すことでこれらのチャネルの使用をバイパスしないことを確認します。

## 参考情報

### OWASP MASVS

- MSTG-NETWORK-1: "データはネットワーク上でTLSを使用して暗号化されている。セキュアチャネルがアプリ全体を通して一貫して使用されている。"
- MSTG-NETWORK-2: "TLS 設定は現在のベストプラクティスと一致している。モバイルオペレーティングシステムが推奨される標準規格をサポートしていない場合には可能な限り近い状態である。"
- MSTG-NETWORK-5: "アプリは登録やアカウントリカバリーなどの重要な操作において（電子メールやSMSなどの）単方向のセキュアでない通信チャネルに依存していない。"

### Android

- Android supported Cipher suites - <https://developer.android.com/reference/javax/net/ssl/SSLSocket#Cipher%20suites>
- Android documentation: Android 10 Changes - <https://developer.android.com/about/versions/10/behavior-changes-all>

### iOS

- iOS supported Cipher suites - <https://developer.apple.com/documentation/security/1550981-ssl_cipher_suite_values?language=objc>

### IANA Transport Layer Security (TLS) Parameters

- TLS Cipher Suites - <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4>

### OWASP TLS Cipher String Cheat Sheet

- Recommendations for a cipher string - <https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/TLS_Cipher_String_Cheat_Sheet.md>

### SIM Swapping attacks

- The SIM Hijackers - <https://motherboard.vice.com/en_us/article/vbqax3/hackers-sim-swapping-steal-phone-numbers-instagram-bitcoin>
- SIM swapping: how the mobile security feature can lead to a hacked bank account - <https://www.fintechnews.org/sim-swapping-how-the-mobile-security-feature-can-lead-to-a-hacked-bank-account/>

### NIST

- FIPS PUB 186 - Digital Signature Standard (DSS)

### SIM Swap Fraud

- <https://motherboard.vice.com/en_us/article/vbqax3/hackers-sim-swapping-steal-phone-numbers-instagram-bitcoin>
- How to protect yourself against a SIM swap attack - <https://www.wired.com/story/sim-swap-attack-defend-phone/>

<br/>
<br/>

### IETF

- RFC 6176 - <https://tools.ietf.org/html/rfc6176>
- RFC 6101 - <https://tools.ietf.org/html/rfc6101>
- RFC 2246 - <https://www.ietf.org/rfc/rfc2246>
- RFC 4346 - <https://tools.ietf.org/html/rfc4346>
- RFC 5246 - <https://tools.ietf.org/html/rfc5246>
- RFC 8446 - <https://tools.ietf.org/html/rfc8446>
- RFC 6979 - <https://tools.ietf.org/html/rfc6979>
- RFC 8017 - <https://tools.ietf.org/html/rfc8017>
- RFC 2631 - <https://tools.ietf.org/html/rfc2631>
- RFC 7919 - <https://tools.ietf.org/html/rfc7919>
- RFC 4492 - <https://tools.ietf.org/html/rfc4492>
- RFC 4279 - <https://tools.ietf.org/html/rfc4279>
- RFC 2631 - <https://tools.ietf.org/html/rfc2631>
- RFC 8422 - <https://tools.ietf.org/html/rfc8422>
- RFC 5489 - <https://tools.ietf.org/html/rfc5489>
- RFC 4772 - <https://tools.ietf.org/html/rfc4772>
- RFC 1829 - <https://tools.ietf.org/html/rfc1829>
- RFC 2420 - <https://tools.ietf.org/html/rfc2420>
- RFC 3268 - <https://tools.ietf.org/html/rfc3268>
- RFC 5288 - <https://tools.ietf.org/html/rfc5288>
- RFC 7465 - <https://tools.ietf.org/html/rfc7465>
- RFC 7905 - <https://tools.ietf.org/html/rfc7905>
- RFC 7539 - <https://tools.ietf.org/html/rfc7539>
- RFC 6151 - <https://tools.ietf.org/html/rfc6151>
- RFC 6234 - <https://tools.ietf.org/html/rfc6234>
- RFC 8447 - <https://tools.ietf.org/html/rfc8447#section-8>
