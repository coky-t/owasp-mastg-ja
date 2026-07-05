---
masvs_category: MASVS-RESILIENCE
platform: ios
title: ファイル完全性チェック (File Integrity Checks)
---

ファイル完全性をチェックするにはアプリケーションのソースコードの完全性チェックを使用するものとファイルストレージの完全性チェックを使用するものの二つの一般的なアプローチがあります。

## アプリケーションのソースコードの完全性チェック

[デバッグ (Debugging)](../../../techniques/ios/MASTG-TECH-0084.md) では、iOS IPA アプリケーションの署名チェックについて説明しています。また、リバースエンジニアは開発者証明書やエンタープライズ証明書を使用してアプリを再パッケージおよび再署名することで、このチェックをバイパスできることも学びました。これをより困難にする方法のひとつは、署名が実行時に一致するかどうかをチェックするカスタムチェックを追加することです。

Apple は DRM を使用して完全性チェックを行います。しかし、 (以下の例にあるように) 制御を追加できます。 `mach_header` を解析し、署名を生成するために使用される命令データの開始を計算します。次に、署名を与えられたものと比較します。生成された署名がどこに格納もしくはコード化されているか確認します。

```c
int xyz(char *dst) {
    const struct mach_header * header;
    Dl_info dlinfo;

    if (dladdr(xyz, &dlinfo) == 0 || dlinfo.dli_fbase == NULL) {
        NSLog(@" Error: Could not resolve symbol xyz");
        [NSThread exit];
    }

    while(1) {

        header = dlinfo.dli_fbase;  // Pointer on the Mach-O header
        struct load_command * cmd = (struct load_command *)(header + 1); // First load command
        // Now iterate through load command
        //to find __text section of __TEXT segment
        for (uint32_t i = 0; cmd != NULL && i < header->ncmds; i++) {
            if (cmd->cmd == LC_SEGMENT) {
                // __TEXT load command is a LC_SEGMENT load command
                struct segment_command * segment = (struct segment_command *)cmd;
                if (!strcmp(segment->segname, "__TEXT")) {
                    // Stop on __TEXT segment load command and go through sections
                    // to find __text section
                    struct section * section = (struct section *)(segment + 1);
                    for (uint32_t j = 0; section != NULL && j < segment->nsects; j++) {
                        if (!strcmp(section->sectname, "__text"))
                            break; //Stop on __text section load command
                        section = (struct section *)(section + 1);
                    }
                    // Get here the __text section address, the __text section size
                    // and the virtual memory address so we can calculate
                    // a pointer on the __text section
                    uint32_t * textSectionAddr = (uint32_t *)section->addr;
                    uint32_t textSectionSize = section->size;
                    uint32_t * vmaddr = segment->vmaddr;
                    char * textSectionPtr = (char *)((int)header + (int)textSectionAddr - (int)vmaddr);
                    // Calculate the signature of the data,
                    // store the result in a string
                    // and compare to the original one
                    unsigned char digest[CC_MD5_DIGEST_LENGTH];
                    CC_MD5(textSectionPtr, textSectionSize, digest);     // calculate the signature
                    for (int i = 0; i < sizeof(digest); i++)             // fill signature
                        sprintf(dst + (2 * i), "%02x", digest[i]);

                    // return strcmp(originalSignature, signature) == 0;    // verify signatures match

                    return 0;
                }
            }
            cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
        }
    }

}
```

**バイパス:**

1. アンチデバッグ機能にパッチを当て、関連するコードを NOP 命令で上書きすることで望ましくない動作を無効にします。
2. コードの完全性を評価するために使用される保存されたハッシュにパッチを当てます。
3. Frida を使用してファイルシステム API をフックして、改変したファイルではなく元のファイルへのハンドルを返します。

## ファイルストレージの完全性チェック

アプリはキーチェーン、`UserDefaults`/`NSUserDefaults`、任意のデータベースなど、特定のキーバリューペアやデバイス上に保存されているファイルに対して HMAC やシグネチャを作成することで、アプリケーションストレージ自体の完全性を確保することを選択することがあります。

たとえば、アプリには `CommonCrypto` で HMAC を生成する以下のようなコードが含まれているかもしれません。

```objectivec
    // Allocate a buffer to hold the digest and perform the digest.
    NSMutableData* actualData = [getData];
    //get the key from the keychain
    NSData* key = [getKey];
    NSMutableData* digestBuffer = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, [actualData bytes], (CC_LONG)[key length], [actualData bytes], (CC_LONG)[actualData length], [digestBuffer mutableBytes]);
    [actualData appendData: digestBuffer];
```

このスクリプトは以下の手順を実行します。

1. データを `NSMutableData` として取得します。
2. データキーを (一般的にキーチェーンから) 取得します。
3. ハッシュ値を計算します。
4. ハッシュ値を実データに追加します。
5. 手順 4. の結果を格納します。

その後、以下のようにして HMAC を検証していることがあります。

```objectivec
  NSData* hmac = [data subdataWithRange:NSMakeRange(data.length - CC_SHA256_DIGEST_LENGTH, CC_SHA256_DIGEST_LENGTH)];
  NSData* actualData = [data subdataWithRange:NSMakeRange(0, (data.length - hmac.length))];
  NSMutableData* digestBuffer = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
  CCHmac(kCCHmacAlgSHA256, [actualData bytes], (CC_LONG)[key length], [actualData bytes], (CC_LONG)[actualData length], [digestBuffer mutableBytes]);
  return [hmac isEqual: digestBuffer];
```

1. メッセージと HMAC バイトを個別の `NSData` として抽出します。
2. `NSData` で HMAC を生成する手順 1-3 を繰り返します。
3. 抽出された HMAC バイトを手順 1 の結果と比較します。

注: アプリがファイルの暗号化も行う場合には、 [Authenticated Encryption](https://web.archive.org/web/20210804035343/https://cseweb.ucsd.edu/~mihir/papers/oem.html "Authenticated Encryption: Relations among notions and analysis of the generic composition paradigm") で説明されているように、暗号化してから HMAC を計算するようにします。

**バイパス:**

1. [デバイスバインディング (Device Binding)](MASTG-KNOW-0090.md) セクションで説明されているように、デバイスからデータを取得します。
2. 取得したデータを改変してストレージに戻します。
