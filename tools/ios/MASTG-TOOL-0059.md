---
title: optool
platform: ios
source: https://github.com/alexzielenski/optool
---

optool は、ロードコマンドの挿入/削除、コード署名の削除、再署名、aslr の削除を行うために、MachO バイナリとインタフェースするツールです。

インストールするには:

```bash
git clone https://github.com/alexzielenski/optool.git
cd optool/
git submodule update --init --recursive
xcodebuild
ln -s <your-path-to-optool>/build/Release/optool /usr/local/bin/optool
```

最終行ではシンボリックリンクを作成し、実行ファイルをシステム全体で利用できるようにします。シェルをリロードして、新しいコマンドを利用できるようにします。

```bash
zsh: # . ~/.zshrc
bash: # . ~/.bashrc
```
