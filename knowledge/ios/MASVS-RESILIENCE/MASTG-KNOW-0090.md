---
masvs_category: MASVS-RESILIENCE
platform: ios
title: デバイスバインディング (Device Binding)
---

デバイスバインディングの目的は、デバイス A からデバイス B へアプリとその状態をコピーし、デバイス B 上でアプリの実行を継続しようとする攻撃者を妨害することです。デバイス A が信頼されていると判断された後、デバイス B よりも多くの権限を持つ可能性があります。アプリをデバイス A からデバイス B へコピーする際にこの状況を変更すべきではありません。

[iOS 7.0 以降](https://developer.apple.com/library/content/releasenotes/General/RN-iOSSDK-7.0/index.html "iOS 7 release notes")、ハードウェア識別子 (MAC アドレスなど) は制限されていますが、iOS でデバイスバインディングを実装する他の方法があります。

- **`identifierForVendor`**: `[[UIDevice currentDevice] identifierForVendor]` (Objective-C の場合), `UIDevice.current.identifierForVendor?.uuidString` (Swift3 の場合), `UIDevice.currentDevice().identifierForVendor?.UUIDString` (Swift2 の場合) を使用できます。同じベンダーの他のアプリをインストールした後にアプリを再インストールすると `identifierForVendor` の値は同じにならないことがあり、アプリバンドル名を更新すると変わることがあります。したがって、キーチェーン内の何かと組み合わせるのが最良です。
- **キーチェーンの使用**: アプリケーションのインスタンスを識別するためにキーチェーンに何かを保存できます。このデータがバックアップされないようにするには `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` (データを保護し、パスコードや Touch ID の要件を適切に実施したい場合), `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` を使用します。
- **Google Instance ID の使用**: [iOS の実装はこちら](https://developers.google.com/instance-id/guides/ios-implementation "iOS implementation Google Instance ID") を参照してください。

これらのメソッドに基づくスキームはパスコードや Touch ID が有効で、キーチェーンやファイルシステムに保存されているマテリアルが保護クラス (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` や `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` など) で保護されていて、 `SecAccessControlCreateFlags` が `kSecAccessControlDevicePasscode` (パスコード用), `kSecAccessControlUserPresence` (パスコード、Face ID または Touch ID), `kSecAccessControlBiometryAny` (Face ID または Touch ID), `kSecAccessControlBiometryCurrentSet` (Face ID / Touch ID: ただし、現在登録されている生体認証のみ) のいずれかに設定されているとより安全です。
