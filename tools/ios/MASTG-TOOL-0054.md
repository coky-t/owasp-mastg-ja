---
title: ios-deploy
platform: ios
source: https://github.com/ios-control/ios-deploy
---

[ios-deploy](https://github.com/ios-control/ios-deploy "ios-deploy") では、Xcode を使用せずにコマンドラインから iOS アプリをインストールおよびデバッグできます。macOS では brew 経由でインストールできます。

```bash
brew install ios-deploy
```

代替手段:

```bash
git clone https://github.com/ios-control/ios-deploy.git
cd ios-deploy/
xcodebuild
cd build/Release
./ios-deploy
ln -s <your-path-to-ios-deploy>/build/Release/ios-deploy /usr/local/bin/ios-deploy
```

最終行ではシンボリックリンクを作成し、実行ファイルをシステム全体で利用できるようにします。シェルをリロードして、新しいコマンドを利用できるようにします。

```bash
zsh: # . ~/.zshrc
bash: # . ~/.bashrc
```
