---
title: MobSF
platform: generic
source: https://github.com/MobSF/Mobile-Security-Framework-MobSF
---

[MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF "MobSF") (Mobile Security Framework) は自動化されたオールインワンのモバイルアプリケーションのペンテストフレームワークであり、静的解析および動的解析を実行できます。MobSF を始める最も簡単な方法は Docker を介することです。

```bash
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

または、以下を実行して、ホストコンピュータ上にローカルにインストールして起動します。

```bash
# Setup
git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
cd Mobile-Security-Framework-MobSF
./setup.sh # For Linux and Mac
setup.bat # For Windows

# Installation process
./run.sh # For Linux and Mac
run.bat # For Windows
```

MobSF を起動したら、ブラウザで <http://127.0.0.1:8000> に移動して開くことができます。解析したい APK を upload エリアにドラッグするだけで、MobSF は作業を開始します。
