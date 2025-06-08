---
masvs_v1_id:
- MSTG-AUTH-8
- MSTG-STORAGE-11
masvs_v2_id:
- MASVS-AUTH-2
platform: ios
title: 生体認証のテスト (Testing Biometric Authentication)
masvs_v1_levels:
- L2
profiles: [L2]
status: deprecated
covered_by: [MASTG-TEST-0266, MASTG-TEST-0267, MASTG-TEST-0268, MASTG-TEST-0269, MASTG-TEST-0270, MASTG-TEST-0271]
deprecation_note: New version available in MASTG V2
---

## 概要

アプリ内のフレームワークの使用はアプリバイナリの共有ダイナミックライブラリのリストを解析することによって検出できます。これは [otool](../../../tools/ios/MASTG-TOOL-0060.md) を使用して実行できます。

```bash
otool -L <AppName>.app/<AppName>
```

アプリで `LocalAuthentication.framework` が使用されている場合、その出力には以下の行が両方含まれます (`LocalAuthentication.framework` は内部で `Security.framework` を使用することを忘れないでください) 。

```bash
/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication
/System/Library/Frameworks/Security.framework/Security
```

`Security.framework` が使用されている場合、二番目のものだけが表示されます。

## 静的解析

LocalAuthentication フレームワークはイベントベースのプロシージャであるため、認証の唯一の方法であるべきではないことを覚えておくことが重要です。このタイプの認証はユーザーインタフェースレベルでは有効ですが、パッチ適用や計装によって簡単にバイパスされます。したがって、キーチェーンサービスメソッドを使用するのが最善です。つまり、以下を行うべきです。

- 支払いトランザクションを実行するユーザーの再認証などの機密性の高いプロセスが、キーチェーンサービスメソッドを使用して保護されていることを検証します。
- ユーザーの認証によってのみキーチェーンアイテムのデータをロック解除できるようにするアクセス制御フラグがキーチェーンアイテムに設定されていることを検証します。これには以下のいずれかのフラグで実行できます。
    - `kSecAccessControlBiometryCurrentSet` (iOS 11.3 以前では `kSecAccessControlTouchIDCurrentSet`) 。これによりユーザーがキーチェーンアイテムのデータにアクセスする前に、ユーザーが生体情報 (Face ID や Touch ID など) で認証する必要があることを確実にします。ユーザーがデバイスに指紋や顔の表現を追加すると、キーチェーンのエントリが自動的に無効になります。これによりアイテムがキーチェーンに追加されたときに登録されていたユーザーのみがキーチェーンアイテムのロックを解除できるようになります。
    - `kSecAccessControlBiometryAny` (iOS 11.3 以前では `kSecAccessControlTouchIDAny`) 。これによりユーザーがキーチェーンアイテムのデータにアクセスする前に、ユーザーが生体情報 (Face ID や Touch ID など) で認証する必要があることを確実にします。キーチェーンエントリは新しい指紋や顔の表現を (再) 登録しても存続します。ユーザーの指紋が変化している場合、これは非常に便利です。但し、指紋や顔の表現を何らかの方法でデバイスに登録できる攻撃者は、これらのエントリにもアクセスできることも意味します。
    - `kSecAccessControlUserPresence` を代替として使用できます。これにより生体認証が機能しない場合に、ユーザーはパスコードを介して認証できます。Touch ID や Face ID サービスをバイパスするよりも、ショルダーサーフィンによって誰かのパスコードエントリを盗むほうがはるかに簡単であるため、`kSecAccessControlBiometryAny` よりも脆弱であると考えられます。
- 生体情報を使用できるようにするために、`SecAccessControlCreateWithFlags` メソッドがコールされたときに `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` または `kSecAttrAccessibleWhenPasscodeSet` 保護クラスが設定されていることを検証します。`...ThisDeviceOnly` バリアントはキーチェーンアイテムが他の iOS デバイスと同期されないようにすることに注意します。

> 注意、データ保護クラスはデータをセキュアにするために使用されるアクセス方法を指定します。各クラスは異なるポリシーを使用して、いつデータにアクセス可能となるかを決定します。


## 動的解析

[Objection Biometrics Bypass](https://github.com/sensepost/objection/wiki/Understanding-the-iOS-Biometrics-Bypass "Understanding the iOS Biometrics Bypass") を使用して LocalAuthentication をバイパスできます。 Objection は Frida を使用して `evaluatePolicy` 関数を計装し、認証が成功しなかった場合でも `True` を返します。 `ios ui biometrics_bypass` コマンドを使用して、セキュアではない生体認証をバイパスします。 Objection はジョブを登録して `evaluatePolicy` の結果を置き換えます。 Swift と Objective-C の両方の実装で機能します。

```bash
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # ios ui biometrics_bypass
(agent) Registering job 3mhtws9x47q. Type: ios-biometrics-disable
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # (agent) [3mhtws9x47q] Localized Reason for auth requirement: Please authenticate yourself
(agent) [3mhtws9x47q] OS authentication response: false
(agent) [3mhtws9x47q] Marking OS response as True instead
(agent) [3mhtws9x47q] Biometrics bypass hook complete
```

脆弱な場合、モジュールはログインフォームを自動的にバイパスします。
