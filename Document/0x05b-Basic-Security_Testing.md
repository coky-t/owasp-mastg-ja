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

#### Testing on the Emulator

All of the above steps to prepare a hardware testing device do also apply if an emulator is used<sup>[4]</sup>. For dynamic testing several tools or VMs are available that can be used to test an app within an emulator environment:

* AppUse
* MobSF

It is also possible to simply create an AVD and use this for testing.

##### Setting Up a Web Proxy on Virtual Device

To set up a HTTP proxy on the emulator follow the following procedure, which works on the Android emulator shipping with Android Studio 2.x:

1. Set up your proxy to listen on localhost. Reverse-forward the proxy port from the emulator to the host, e.g.:

```bash
$ adb reverse tcp:8080 tcp:8080
```

2. Configure the HTTP proxy in the access point settings of the device:
- Open the Settings Menu
- Tap on "Wireless & Networks" -> "Cellular Networks" or "Mobile Networks"
- Open "Access Point Names"
- Open the existing APN (e.g. "T-Mobile US")
- Enter "127.0.0.1" in the "Proxy" field and your proxy port in the "Port" field (e.g. "8080")
- Open the top-right menu and tap "save"

<img width=300px src="Images/Chapters/0x05b/emulator-proxy.jpg"/>

HTTP and HTTPS requests should now be routed over the proxy on the host machine. Try toggling airplane mode off and on if it doesn't work.

##### Installing a CA Certificate on the Virtual Device

An easy way to install a CA certificate is pushing the cert to the device and adding it to the certificate store via Security Settings. For example, you can install the PortSwigger (Burp) CA certificate as follows:

1. Start Burp and navigate to http://burp/ using a web browser on the host, and download cacert.der by clicking the "CA Certificate" button.
2. Change the file extension from .der to .cer
3. Push the file to the emulator:

```bash
$ adb push cacert.cer /sdcard/
```

4. Navigate to "Settings" -> "Security" -> "Install from SD Card"
5. Scroll down and tap on "cacert.cer"

You should now be prompted to confirm installation of the certificate (you'll also be asked to set a device PIN if you haven't already).

##### Connecting to an Android Virtual Device (AVD) as Root

An Android Virtual Device (AVD) can be created by using the AVD manager, which is available within Android Studio<sup>[5]</sup>. The AVD manager can also be started separately from the command line by using the `android` command in the tools directory of the Android SDK:

```bash
$ ./android avd
```

Once the emulator is up and running a root connection can be established by using `adb`.

```bash
$ adb root
$ adb shell
root@generic_x86:/ $ id
uid=0(root) gid=0(root) groups=0(root),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats) context=u:r:su:s0
```

Rooting of an emulator is therefore not needed as root access can be granted through `adb`.

##### Restrictions When Testing on an Emulator

There are several downsides when using an emulator. You might not be able to test an app properly in an emulator, if it's relying on the usage of a specific mobile network, or uses NFC or Bluetooth. Testing within an emulator is usually also slower in nature and might lead to issues on its own.

Nevertheless several hardware characteristics can be emulated, like GPS<sup>[6]</sup> or SMS<sup>[7]</sup> and many more.


#### Potential Obstacles

For the following security controls that might be implemented into the app you are about to test, it should be discussed with the project team if it is possible to provide a debug build. A debug build has several benefits when provided during a (white box) test, as it allows a more comprehensive analysis.

##### SSL Pinning

SSL Pinning is a mechanism to make dynamic analysis harder. Certificates provided by an interception proxy to enable a Man-in-the-middle position are declined and the app will not make any requests. To be able to efficiently test during a white box test, a debug build with deactivated SSL Pinning should be provided.

For a black box test, there are several ways to bypass SSL Pinning, for example SSLUnpinning<sup>[11]</sup> or Android-SSL-TrustKiller<sup>[12]</sup>. Therefore bypassing can be done within seconds, but only if the app uses the API functions that are covered for these tools. If the app is using a different framework or library to implement SSL Pinning that is not implemented yet in those tools, the patching and deactivation of SSL Pinning needs to be done manually and can become time consuming.

To manually deactivate SSL Pinning there are two ways:
* Dynamical Patching while running the App, by using Frida<sup>[9] [13]</sup> or ADBI<sup>[10]</sup>
* Disassembling the APK, identify the SSL Pinning logic in smali code, patch it and reassemble the APK<sup>[7] [22]</sup>

Once successful, the prerequisites for a dynamic analysis are met and the apps communication can be investigated.

See also test case "Testing Custom Certificate Stores and SSL Pinning" for further details.

##### Root Detection

Root detection can be implemented using pre-made libraries like RootBeer<sup>[14]</sup> or custom checks. An extensive list of root detection methods is presented in the "Testing Anti-Reversing Defenses on Android" chapter.

In a typical mobile app security build, you'll usually want to test a debug build with root detection disabled. If such a build is not available for testing, root detection can be disabled using a variety of methods which will be introduced later in this book.

### Testing Methods

#### Static Analysis

Static analysis is the act of looking into app components, source code and other resources without actually executing it. This test is focused on finding misconfigured or unprotected Android IPC components, as well as finding programming mistakes such as misuse of cryptography routines, find libraries with known vulnerabilities and even dynamic code loading routines.

Static analysis should be supported through the usage of tools, to make the analysis efficient and to allow the tester to focus on the more complicated business logic. There are a plethora of static code analyzers that can be used, ranging from open source scanners to full blown enterprise ready scanners. The decision on which tool to use depends on the budget, requirements by the client and the preferences of the tester.

Some Static Analyzers rely on the availability of the source code while others take the compiled APK as input.
It is important to keep in mind that while static analyzers can help us to focus attention on potential problems, they may not be able to find all the problems by itself. Go through each finding carefully and try to understand what the app is doing to improve your chances of finding vulnerabilities.

One important thing to note is to configure the static analyzer properly in order to reduce the likelihood of false positives and maybe only select several vulnerability categories in the scan. The results generated by static analyzers can otherwise be overwhelming and the effort can become counterproductive if an overly large report need to be manually investigated.

Static Analysis can be divided into two categories, **White box** and **Black box**. The first is when the source code is available and the other is when we only have the compiled application or library. We will now go into more details on each category.

##### Static Analysis with Source Code ("White-Box")

**White box testing** an app is the act of testing an app with the source code available. To accomplish the source code testing, you will want to have a setup similar to the developer. You will need a testing environment on your machine with the Android SDK and an IDE installed. It is also recommended to have access either to a physical device or an emulator, so you can debug the app.

Once you have the setup ready and the source code indexed by an IDE (Android Studio is recommended since it is the current IDE of choice by Google), you can start debugging and searching for interesting parts of code.
Begin by testing each [Android Component](0x05a-Platform-Overview.md#app-components). Check whether they are exported and the enforcing permissions that are in place. Android Lint<sup>[15]</sup> can help in the identification of such problems. Any Android component manipulating sensitive data (contacts, location, images, etc.) should be investigated carefully.

Proceed on to testing the libraries the application has embedded: some libraries contain known vulnerabilities and you should check for that. Some of the question you may want to answer are: what libraries are the app using? Which version of the libraries are being used? Do they have any known vulnerability?

Since you have the source code in hand, you can check for cryptographic mistakes in the implementation. Look for hard coded keys and implementation errors related to cryptography functions. Devknox<sup>[16]</sup> can help checking most common cryptographic mistakes since it is embedded to the IDE.

##### Static Analysis without Source Code ("Black-Box")

During **Black box testing** you will not have access to the source code in its original form. Usually, you will have the application package in hand (in Android .apk format<sup>[17]</sup>), which can be installed on an Android device or reverse engineered with the goal to retrieve parts of the source code.

An easy way on the CLI to retrieve the source code of an APK is through <code>apkx</code>, which also packages <code>dex2jar</code> and CFR and automates the extracting, conversion and decompilation steps. Install it as follows:

```
$ git clone https://github.com/b-mueller/apkx
$ cd apkx
$ sudo ./install.sh
```

This should copy <code>apkx</code> to <code>/usr/local/bin</code>. Run it on the APK that need to be tested:

```bash
$ apkx UnCrackable-Level1.apk
Extracting UnCrackable-Level1.apk to UnCrackable-Level1
Converting: classes.dex -> classes.jar (dex2jar)
dex2jar UnCrackable-Level1/classes.dex -> UnCrackable-Level1/classes.jar
Decompiling to UnCrackable-Level1/src (cfr)
```

If the application is based solely on Java and does not have any native library (code written in C/C++), the reverse engineering process is relatively easy and recovers almost the entire source code. Nevertheless, if the code is obfuscated, this process might become very time consuming and might not be productive. The same applies for applications that contain a native library. They can still be reverse engineered but require low level knowledge and the process is not automated.

More details and tools about the Android reverse engineering topic can be found at [Tampering and Reverse Engineering on Android](0x05b-Reverse-Engineering-and-Tampering.md) section.

Besides reverse engineering, there is a handful of automated tools that perform security analysis on the APK itself searching for vulnerabilities.
Some of these tools are:
* QARK<sup>[18]</sup>,
* Androbugs<sup>[19]</sup> and
* JAADAS<sup>[20]</sup>.

#### Dynamic Analysis

Compared to static analysis, dynamic analysis is applied while executing the mobile app. The test cases can range from investigating the file system and changes made to it on the mobile device to monitoring the communication with the endpoint while using the app.

When we talk about dynamic analysis of applications that rely on the HTTP(S) protocol, several tools can be used to support the dynamic analysis. The most important tools are so called interception proxies, like OWASP ZAP or Burp Suite Professional to name the most famous ones. An interception proxy allows the tester to have a Man-in-the-middle position in order to read and/or modify all requests made from the app and responses coming from the endpoint for testing Authorization, Session Management and so on.

#### Drozer

Drozer<sup>[25]</sup> is an Android security assessment framework that allows you to search for security vulnerabilities in apps and devices by assuming the role of a third party app interacting with the other application's IPC endpoints and the underlying OS. The following section documents the steps necessary to install and begin using Drozer.

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
