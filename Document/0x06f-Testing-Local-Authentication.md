---
masvs_category: MASVS-AUTH
platform: ios
---

# iOS のローカル認証

## 概要

ローカル認証では、アプリはデバイス上でローカルに保存されたクレデンシャルに対してユーザーを認証します。言い換えると、ユーザーはローカルデータを参照することにより検証される PIN、パスワード、または顔や指紋などの生体特性を提供することで、アプリや機能の何かしらの内部層を「アンロック」します。一般的に、これはユーザーがより便利にリモートサービスでの既存のセッションを再開するため、またはある重要な機能を保護するためのステップアップ認証の手段として行われます。

["モバイルアプリの認証アーキテクチャ"](0x04e-Testing-Authentication-and-Session-Management.md) の章で前述しているように、テスト技術者はローカル認証が常にリモートエンドポイントで実行されることや暗号プリミティブに基づいている必要があることに注意します。認証プロセスからデータが返らない場合、攻撃者は簡単にローカル認証をバイパスできます。

アプリにローカル認証を統合するためのさまざまな方法が用意されています。[Local Authentication framework](https://developer.apple.com/documentation/localauthentication "Local Authentication framework") では開発者がユーザーへの認証ダイアログを拡張するための一連の API が提供されています。リモートサービスに接続するコンテキストでは、ローカル認証を実装するに [キーチェーン](https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/01introduction/introduction.html "Keychain Services") を利用することが可能であり (および推奨され) ます。

iOS での指紋認証は _Touch ID_ として知られています。指紋 ID センサーは [SecureEnclave security coprocessor](https://www.blackhat.com/docs/us-16/materials/us-16-Mandt-Demystifying-The-Secure-Enclave-Processor.pdf "Demystifying the Secure Enclave Processor by Tarjei Mandt, Mathew Solnik, and David Wang") により操作され、指紋データをシステムの他の部分に開示することはありません。Touch ID の次に、Apple は顔認識に基づく認証を可能にする _Face ID_ を導入しました。いずれもアプリケーションレベルで、データを格納し、データを格納する実際の手法として、似たような API を使用します (例えば、顔データと指紋関連データが異なります) 。

開発者には Touch ID/FaceID 認証を組み込むために二つの選択肢があります。

- `LocalAuthentication.framework` は上位レベルの API であり、Touch ID 経由でユーザーを認証するために使用できます。アプリは登録された指紋に関連付けられたデータにアクセスすることはできません。認証が成功したかどうかだけが通知されます。
- `Security.framework` は下位レベルの API であり、[keychain services](https://developer.apple.com/documentation/security/keychain_services "keychain Services") にアクセスします。アプリが生体認証である機密データを保護する必要がある場合、アクセス制御はシステムレベルで管理され、簡単にはバイパスできないため、これは安全な選択肢です。`Security.framework` には C API がありますが、いくつかの [オープンソースラッパーを利用](https://www.raywenderlich.com/147308/secure-ios-user-data-keychain-touch-id "How To Secure iOS User Data: The keychain and Touch ID") して、キーチェーンへのアクセスを NSUserDefaults のように簡単に行えます。`Security.framework` は `LocalAuthentication.framework` の基礎にあります。Apple は可能であれば上位レベル API をデフォルトとすることを推奨しています。

`LocalAuthentication.framework` または `Security.framework` のいずれかを使用すると、ブール値を返すだけで処理を続けるデータがないため、攻撃者がバイパスできるコントロールになることに注意します。詳細については [Don't touch me that way, by David Lindner et al](https://www.youtube.com/watch?v=XhXIHVGCFFM "Don\'t Touch Me That Way - David Lindner") を参照してください。
