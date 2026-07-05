---
masvs_category: MASVS-RESILIENCE
platform: ios
title: 脱獄検出 (Jailbreak Detection)
---

# MASTG-KNOW-0084

脱獄検出メカニズムがリバースエンジニアリング防御に追加されると、脱獄済みデバイス上でのアプリ実行がより困難になります。これによりリバースエンジニアが使用したいツールや技法の一部がブロックされます。他のほとんどの種類の防御の場合と同様に、脱獄検出自体はあまり効果的ではありませんが、アプリのソースコード全体にチェックを分散されることで改竄防止スキーム全体の有効性を向上させることができます。

> 脱獄検出やルート検出についての詳細は Dana Geist と Marat Nigmatullin による調査研究 ["Jailbreak/Root Detection Evasion Study on iOS and Android"](https://github.com/crazykid95/Backup-Mobile-Security-Report/blob/master/Jailbreak-Root-Detection-Evasion-Study-on-iOS-and-Android.pdf) を参照してください。

### 一般的な脱獄検出チェック

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

### 脱獄検出のバイパス

その存在の検出だけでなく、これらのチェックは動的計装ツールや手動リバースエンジニアリングを使用して回避できることが多くあります。[脱獄検出のバイパス (Bypassing Jailbreak Detection)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0152.md) では脱獄検出の実装を特定してバイパスするために使用される技法を説明しています。
