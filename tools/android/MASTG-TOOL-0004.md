---
title: adb
platform: android
---

[adb](https://developer.android.com/studio/command-line/adb "Android Debug Bridge") (Android Debug Bridge) は Android SDK に同梱されており、ローカル開発環境と、接続された Android デバイスとの間のギャップを埋めます。通常、エミュレータや、USB や Wi-Fi 経由で接続されたデバイスでアプリをテストするためにこれを活用します。`adb devices` コマンドを使用して、接続されたデバイスを一覧表示し、`-l` 引数を付けて実行することでそれらの詳細を取得できます。

```bash
$ adb devices -l
List of devices attached
090c285c0b97f748 device usb:1-1 product:razor model:Nexus_7 device:flo
emulator-5554    device product:sdk_google_phone_x86 model:Android_SDK_built_for_x86 device:generic_x86 transport_id:1
```

adb は他にも、ターゲット上で対話型シェルを起動する `adb shell` や、特定のホストポート上のトラフィックを、接続されたデバイス上の別のポートに転送する `adb forward` などの便利なコマンドを提供します。

```bash
adb forward tcp:<host port> tcp:<device port>
```

```bash
$ adb -s emulator-5554 shell
root@generic_x86:/ # ls
acct
cache
charger
config
...
```

本書の後半で、テスト時に adb コマンドをどのように使用するかについてさまざまなユースケースを紹介します。複数のデバイスを接続している場合には、ターゲットデバイスのシリアル番号を `-s` 引数で (前のコードスニペットで示されているように) 定義しなければならないことに注意してください。
