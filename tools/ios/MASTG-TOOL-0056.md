---
title: Keychain-Dumper
platform: ios
source: https://github.com/ptoomey3/Keychain-Dumper
---

[Keychain-dumper](https://github.com/ptoomey3/Keychain-Dumper/releases "keychain-dumper") は、iOS デバイスが脱獄された後に攻撃者が利用できるキーチェーンアイテムをチェックするための iOS ツールです。最新バージョンの iOS でこのツールを使用するには、いくつかの手順に従う必要があります。まず、[Keychain-Dumper リリースページ](https://github.com/ptoomey3/Keychain-Dumper/releases) から最新リリースをダウンロードして、パッケージを unzip します。次に、[updateEntitlements.sh](https://raw.githubusercontent.com/ptoomey3/Keychain-Dumper/refs/heads/master/updateEntitlements.sh) スクリプトを同じディレクトリにダウンロードします。最初の行 (`KEYCHAIN_DUMPER_FOLDER=/usr/bin`) を `KEYCHAIN_DUMPER_FOLDER=/var/jb/usr/bin` に変更して、ルートレス脱獄と互換性を持たせます。デバイスがルート化脱獄 (palera1n など) しているなら、この手順をスキップできます。

```bash
# Copy over the binary to /var/jb/usr/bin/
scp keychain_dumper mobile@<deviceip>:/var/jb/usr/bin/

# Copy over the updateEntitlements.sh script
scp updateEntitlements.sh mobile@<deviceip>:/var/jb/usr/bin/

# SSH into the device
ssh mobile@<deviceip>

# Go to the /var/jb/tmp directory and switch to root
cd /var/jb/usr/bin & sudo su

# Add executable permissions to both files
chmod +x keychain_dumper
chmod +x updateEntitlements.sh

# Run updateEntitlements.sh
./updateEntitlements.sh

# Run keychain_dumper
/var/jb/tmp/keychain_dump -h
```

デフォルトでは、このスクリプトはインストールされているすべてのアプリケーションのキーチェーンを解析するために必要なすべての権限を keychain_dump に付与します。単一のアプリケーションにフォーカスするために、不要な要件をすべて削除できます。

```bash
# Extract entitlements
ldid -e /var/jb/tmp/keychain_dump > ent.xml

# Remove all non-needed entitlements from the <array> segment
nano ent.xml

# Assign the entitlements again
ldid -Sent.xml /var/jb/tmp/keychain_dump
```

使用方法については [Keychain-dumper](https://github.com/mechanico/Keychain-Dumper "keychain-dumper") GitHub ページを参照してください。
