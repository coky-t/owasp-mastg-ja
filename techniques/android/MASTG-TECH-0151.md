---
title: Network Security Configuration の解析 (Analyzing the Network Security Configuration)
platform: android
---

アプリがリバースエンジニアされる ([Android アプリのリバースエンジニアリング (Reverse Engineering Android Apps)](MASTG-TECH-0013.md) 参照) と、Network Security Configuration (NSC) ファイルが出力ディレクトリで入手できます。その場所は AndroidManifest.xml 内の `android:networkSecurityConfig` 属性 ([AndroidManifest の解析 (Analyzing the AndroidManifest)](MASTG-TECH-0150.md) 参照) から導かれており、`@xml/<filename>` という参照は `<output_dir>/res/xml/<filename>.xml` にマップしています。

たとえば、マニフェストが以下を含む場合:

```xml
android:networkSecurityConfig="@xml/network_security_config"
```

NSC ファイルは `output_dir/res/xml/network_security_config.xml` にあります。

## grep を使用する

`grep` を使用して、NSC ファイル内の特定の要素や属性を検索します。

```bash
grep -i "certificates" output_dir/res/xml/network_security_config.xml
```

出力例:

```xml
<certificates src="user"/>
```

## yq を使用する

構造化された XML クエリについては、NSC ファイルに対して `yq` を使用します。

トラストアンカー内のすべての証明書ソースをリストします。

```bash
yq -p=xml -o=json -r '.network-security-config."base-config"."trust-anchors".certificates[]."+@src"' network_security_config.xml
```

出力例:

```txt
system
user
```

`<base-config>` からクリアテキストトラフィック設定を読み取ります。

```bash
yq -p=xml -o=json -r '."network-security-config"."base-config"."+@cleartextTrafficPermitted" // ""' network_security_config.xml
```

出力例:

```txt
true
```

## JSON への変換と jq での取得

`yq` を使用して NSC XML ファイルを JSON に変換すると、`jq` などのツールで解析しやすくなります。

```bash
yq -p=xml -o=json '.' network_security_config.xml > network_security_config.json
```

ここから、`jq` を使用して、証明書ピン留めでのドメインなど、特定の構成について JSON ファイルをクエリします。

```bash
jq -r '
  .["network-security-config"]["domain-config"][]
  | select(.["pin-set"] != null)
  | .domain
  | if type == "object" then .["+content"] else . end
' network_security_config.json
```

出力例:

```txt
example.com
api.example.org
```

## [semgrep](../../tools/generic/MASTG-TOOL-0110.md) を使用する

MASTG のルールとともに [semgrep](../../tools/generic/MASTG-TOOL-0110.md) を使用して、NSC ファイルの安全でないパターンを検出します。たとえば、ユーザーが追加した CA を許可するトラストアンカーを検出するには、以下のようなルールを記述できます。

```yaml
rules:
  - id: mastg-android-network-insecure-trust-anchors
    severity: WARNING
    languages:
      - xml
    match:
      any:
        - <certificates src="user"
```

そして、以下でスキャンを実行します。

```bash
semgrep -c rule.yml network_security_config.xml
```

出力例:

```txt
┌────────────────┐
│ 1 Code Finding │
└────────────────┘

    network_security_config.xml
    ❯❱ rules.mastg-android-network-insecure-trust-anchors

            6┆ <certificates src="user" />
```
