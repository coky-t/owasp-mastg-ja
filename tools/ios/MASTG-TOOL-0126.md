---
title: libimobiledevice suite
platform: ios
host:
- macOS
- windows
- linux
source: https://libimobiledevice.org/
---

libimobiledevice スイートは iOS デバイスとやり取りするためのクロスプラットフォームプロトコルライブラリです。さまざまなライブラリをバイナリにコンパイルして、コマンドラインから iOS デバイスと直接やり取りできます。

!!! 警告

    多くのパッケージリポジトリ (apt, brew, cargo など) に libimobiledevice ツールのバージョンがありますが、古くなっていることがよくあります。最良の結果を得るには、さまざまなツールをソースからコンパイルすることをお勧めします。パッケージマネージャに `-v` に基づく最新バージョンがあるとしても、ソースコードはより新しいものであることに注意してください。

以下のツールは libimobiledevice スイートの一部です。

| ツール | 用途 |
|------------------|---------------------|
| idevice_id | 接続されているデバイスを一覧表示するか、指定されたデバイスのデバイス名を表示します。 |
| idevicebackup | カレントディレクトリまたは指定されたディレクトリからバックアップを作成または復元します (<iOS 4)。 |
| idevicebackup2 | カレントディレクトリまたは指定されたディレクトリからバックアップを作成または復元します (>= iOS 4)。 |
| idevicecrashreport | クラッシュレポートをデバイスからローカル DIRECTORY に移動します。 |
| idevicedate | 現在の日時を表示するか、デバイスに設定します。 |
| idevicedebug | デバイスの debugserver サービスとやり取りします。 |
| idevicedebugserverproxy | デバイスから PORT のローカルソケットへの debugserver 接続をプロキシします。 |
| idevicediagnostics | iOS 4 以降を実行しているデバイスの診断インタフェースを使用します。 |
| ideviceenterrecovery | 指定された UDID を持つデバイスを直ちにリカバリモードにします。 |
| ideviceimagemounter | 指定されたディスクイメージをデバイスにマウントします。 |
| ideviceinfo | 接続されているデバイスについての情報を表示します。 |
| ideviceinstaller | iOS デバイス上のアプリを管理します。 |
| idevicename | デバイス名を表示するか、指定された場合は NAME に設定します。 |
| idevicenotificationproxy | デバイスに通知を投稿または監視します。 |
| idevicepair | デバイスや usbmuxd とのホストペアリングを管理します。 |
| ideviceprovision | デバイスのプロビジョニングプロファイルを管理します。 |
| idevicescreenshot | デバイスからスクリーンショットを取得します。 |
| idevicesetlocation | デバイスの位置情報を設定します。 |
| idevicesyslog | 接続されているデバイスの syslog を中継します。 |
| inetcat | TDIN/STDOUT 経由で usbmux デバイスの TCP ポートへの読み書きインタフェースを開きます。 |
| iproxy | usbmux デバイスの指定されたポートに転送されるローカル TCP ポートをバインドするプロキシです。 |
| plistutil | plist ファイルをバイナリ、XML、JSON、OpenStep 形式の間で変換します。 |
