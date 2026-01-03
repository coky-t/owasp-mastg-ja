---
masvs_category: MASVS-STORAGE
platform: ios
title: Realm データベース (Realm Databases)
---

[Realm Objective-C](https://realm.io/docs/objc/latest/ "Realm Objective-C") と [Realm Swift](https://realm.io/docs/swift/latest/ "Realm Swift") は Apple により提供されているものではありませんが、依然として注目に値します。設定で暗号化を有効にしていない限り、すべて暗号化されずに保存します。

以下の例は Realm データベースで暗号化を使用する方法を示しています。

```swift
// Open the encrypted Realm file where getKey() is a method to obtain a key from the Keychain or a server
let config = Realm.Configuration(encryptionKey: getKey())
do {
  let realm = try Realm(configuration: config)
  // Use the Realm as normal
} catch let error as NSError {
  // If the encryption key is wrong, `error` will say that it's an invalid database
  fatalError("Error opening realm: \(error)")
}
```

データへのアクセスは暗号化に依存します。暗号化されていないデータベースは簡単にアクセスできますが、暗号化されたものは鍵がどのように管理されているか (ハードコードされているか、共有プリファレンスなどの安全でない場所に暗号化されておらずに保存されているか、プラットフォームの KeyStore に安全に保存されているか (ベストプラクティス)) を調査する必要があります。
但し、攻撃者がデバイスへの十分なアクセスを持つ場合 (脱獄済みアクセスなど)、またはアプリを再パッケージ化できる場合、Frida などのツールを使用して実行時に暗号鍵を依然として取得できます。以下の Frida スクリプトは、Realm 暗号鍵を傍受し、暗号化されたデータベースの内容にアクセスする方法を示しています。

```javascript
function nsdataToHex(data) {
    var hexStr = '';
    for (var i = 0; i < data.length(); i++) {
        var byte = Memory.readU8(data.bytes().add(i));
        hexStr += ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }
    return hexStr;
}

function HookRealm() {
    if (ObjC.available) {
        console.log("ObjC is available. Attempting to intercept Realm classes...");
        const RLMRealmConfiguration = ObjC.classes.RLMRealmConfiguration;
        Interceptor.attach(ObjC.classes.RLMRealmConfiguration['- setEncryptionKey:'].implementation, {
            onEnter: function(args) {
                var encryptionKeyData = new ObjC.Object(args[2]);
                console.log(`Encryption Key Length: ${encryptionKeyData.length()}`);
                // Hexdump the encryption key
                var encryptionKeyBytes = encryptionKeyData.bytes();
                console.log(hexdump(encryptionKeyBytes, {
                    offset: 0,
                    length: encryptionKeyData.length(),
                    header: true,
                    ansi: true
                }));

                // Convert the encryption key bytes to a hex string
                var encryptionKeyHex = nsdataToHex(encryptionKeyData);
                console.log(`Encryption Key Hex: ${encryptionKeyHex}`);
            },
            onLeave: function(retval) {
                console.log('Leaving RLMRealmConfiguration.- setEncryptionKey:');
            }
        });

    }

}
```
