---
title: システムログの監視 (Monitoring System Logs)
platform: ios
---

多くのアプリはコンソールログに有益な (そして機密の可能性がある) メッセージをログ記録します。またログにはクラッシュレポートやその他の有用な情報も含みます。コンソールログは Xcode の **Devices** ウィンドウから以下の手順で収集できます。

1. Xcode を起動します。
2. デバイスをホストコンピュータに接続します。
3. **Window** -> **Devices and Simulators** を選択します。
4. Devices ウィンドウの左側のセクションで、接続した iOS デバイスをクリックします。
5. 問題を再現します。
6. Devices ウィンドウの右上にある **Open Console** ボタンをクリックして、別ウィンドウにコンソールログを表示します。

<img src="../../Document/Images/Chapters/0x06b/open_device_console.png" width="100%" />

コンソール出力をテキストファイルに保存するには、Console ウィンドウの右上にある **Save** ボタンをクリックします。

<img src="../../Document/Images/Chapters/0x06b/device_console.png" width="100%" />

[デバイスシェルへのアクセス (Accessing the Device Shell)](MASTG-TECH-0052.md) で説明しているようにデバイスシェルに接続し、apt-get で socat をインストールして、以下のコマンドを実行することもできます。

```bash
iPhone:~ root# socat - UNIX-CONNECT:/var/run/lockdown/syslog.sock

========================
ASL is here to serve you
> watch
OK

Jun  7 13:42:14 iPhone chmod[9705] <Notice>: MS:Notice: Injecting: (null) [chmod] (1556.00)
Jun  7 13:42:14 iPhone readlink[9706] <Notice>: MS:Notice: Injecting: (null) [readlink] (1556.00)
Jun  7 13:42:14 iPhone rm[9707] <Notice>: MS:Notice: Injecting: (null) [rm] (1556.00)
Jun  7 13:42:14 iPhone touch[9708] <Notice>: MS:Notice: Injecting: (null) [touch] (1556.00)
...
```
