---
masvs_category: MASVS-RESILIENCE
platform: ios
title: 脱獄検出 (Jailbreak Detection)
---

脱獄検出メカニズムがリバースエンジニアリング防御に追加されると、脱獄済みデバイス上でのアプリ実行がより困難になります。これによりリバースエンジニアが使用したいツールや技法の一部がブロックされます。他のほとんどの種類の防御の場合と同様に、脱獄検出自体はあまり効果的ではありませんが、アプリのソースコード全体にチェックを分散されることで改竄防止スキーム全体の有効性を向上させることができます。

> 脱獄検出やルート検出についての詳細は Dana Geist と Marat Nigmatullin による調査研究 ["Jailbreak/Root Detection Evasion Study on iOS and Android"](https://github.com/crazykid95/Backup-Mobile-Security-Report/blob/master/Jailbreak-Root-Detection-Evasion-Study-on-iOS-and-Android.pdf "Jailbreak/Root Detection Evasion Study on iOS and Android") を参照してください。

## 一般的な脱獄検出チェック

ここでは三つの典型的な脱獄検出技法を紹介します。

**ファイルベースのチェック:**

アプリは以下のような脱獄に関連する典型的なファイルやディレクトリをチェックしてみる可能性があります。

```default
/Applications/Cydia.app
/Applications/FakeCarrier.app
/Applications/Icy.app
/Applications/IntelliScreen.app
/Applications/MxTube.app
/Applications/RockApp.app
/Applications/SBSettings.app
/Applications/WinterBoard.app
/Applications/blackra1n.app
/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist
/Library/MobileSubstrate/DynamicLibraries/Veency.plist
/Library/MobileSubstrate/MobileSubstrate.dylib
/System/Library/LaunchDaemons/com.ikey.bbot.plist
/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist
/bin/bash
/bin/sh
/etc/apt
/etc/ssh/sshd_config
/private/var/lib/apt
/private/var/lib/cydia
/private/var/mobile/Library/SBSettings/Themes
/private/var/stash
/private/var/tmp/cydia.log
/var/tmp/cydia.log
/usr/bin/sshd
/usr/libexec/sftp-server
/usr/libexec/ssh-keysign
/usr/sbin/sshd
/var/cache/apt
/var/lib/apt
/var/lib/cydia
/usr/sbin/frida-server
/usr/bin/cycript
/usr/local/bin/cycript
/usr/lib/libcycript.dylib
/var/log/syslog
```

**ファイルパーミッションのチェック:**

アプリはアプリケーションのサンドボックスの外にある場所に書き込もうとしてみる可能性があります。たとえば、`/private` ディレクトリにファイルを作成しようとするかもしれません。ファイルが正常に作成された場合、アプリはデバイスが脱獄されていると判断できます。

```swift
do {
    let pathToFileInRestrictedDirectory = "/private/jailbreak.txt"
    try "This is a test.".write(toFile: pathToFileInRestrictedDirectory, atomically: true, encoding: String.Encoding.utf8)
    try FileManager.default.removeItem(atPath: pathToFileInRestrictedDirectory)
    // Device is jailbroken
} catch {
    // Device is not jailbroken
}
```

**プロトコルハンドラのチェック:**

アプリは `cydia://` ([Cydia](../../../tools/ios/MASTG-TOOL-0047.md) をインストール後にデフォルトで利用可能) などのよく知られたプロトコルハンドラを呼び出してみる可能性があります。

```swift
if let url = URL(string: "cydia://package/com.example.package"), UIApplication.shared.canOpenURL(url) {
    // Device is jailbroken
}
```

## 自動化された脱獄検出のバイパス

一般的な脱獄検出メカニズムをバイパスする最も迅速な方法は [objection](../../../tools/generic/MASTG-TOOL-0038.md) です。脱獄バイパスの実装は [jailbreak.ts script](https://github.com/sensepost/objection/blob/master/agent/src/ios/jailbreak.ts "jailbreak.ts") にあります。

## 手動の脱獄検出のバイパス

自動バイパスが有効でない場合、自ら手を動かしてアプリバイナリをリバースエンジニアリングし、検出の原因となるコード部分を見つけ、静的にパッチを当てるかランタイムフックを適用して無効にする必要があります。

**Step 1: リバースエンジニアリング:**

バイナリをリバースエンジニアリングして脱獄検出を探す必要がある場合、最も明白な方法は "jail" や "jailbreak" といった既知の文字列を検索することです。耐性対策が施されている場合や開発者がそのような明白な用語を避けている場合には特に、これは常に有効であるとは限らないことに注意してください。

例: [DVIA-v2](../../../apps/ios/MASTG-APP-0024.md) をダウンロードして unzip し、メインバイナリを [radare2 (iOS)](../../../tools/ios/MASTG-TOOL-0073.md) にロードして解析が完了するまで待ちます。

```sh
r2 -A ./DVIA-v2-swift/Payload/DVIA-v2.app/DVIA-v2
```

これで `is` コマンドを使用してバイナリのシンボルを一覧表示し、文字列 "jail" に対して大文字小文字を区別しない grep (`~+`) を適用できるようになります。

```sh
[0x1001a9790]> is~+jail
...
2230  0x001949a8 0x1001949a8 GLOBAL FUNC 0        DVIA_v2.JailbreakDetectionViewController.isJailbroken.allocator__Bool
7792  0x0016d2d8 0x10016d2d8 LOCAL  FUNC 0        +[JailbreakDetection isJailbroken]
...
```

ご覧のように、シグネチャ `-[JailbreakDetectionVC isJailbroken]` を持つインスタンスメソッドがあります。

**Step 2: 動的フック:**

ここで Frida を使用して、いわゆる early instrumentation、つまり起動時に関数の実装を置き換えることで脱獄検出をバイパスできるようになります。

ホストコンピュータ上で `frida-trace` を使用します。

```bash
frida-trace -U -f /Applications/DamnVulnerableIOSApp.app/DamnVulnerableIOSApp  -m "-[JailbreakDetectionVC isJailbroken]"
```

これによりアプリを起動し、`-[JailbreakDetectionVC isJailbroken]` への呼び出しをトレースし、一致する要素ごとに JavaScript フックを作成します。
お気に入りのエディタで `./__handlers__/__JailbreakDetectionVC_isJailbroken_.js` を開き、 `onLeave` コールバック関数を編集します。 `retval.replace()` を使用して返り値を置き換えるだけで常に `0` を返すようにできます。

```javascript
onLeave: function (log, retval, state) {
    console.log("Function [JailbreakDetectionVC isJailbroken] originally returned:"+ retval);
    retval.replace(0);
    console.log("Changing the return value to:"+retval);
}
```

これにより以下の結果が得られます。

```bash
$ frida-trace -U -f /Applications/DamnVulnerableIOSApp.app/DamnVulnerableIOSApp  -m "-[JailbreakDetectionVC isJailbroken]:"

Instrumenting functions...                                           `...
-[JailbreakDetectionVC isJailbroken]: Loaded handler at "./__handlers__/__JailbreakDetectionVC_isJailbroken_.js"
Started tracing 1 function. Press Ctrl+C to stop.

Function [JailbreakDetectionVC isJailbroken] originally returned:0x1
Changing the return value to:0x0
```
