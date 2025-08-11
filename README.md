# local-subdomains

ローカルネット上でサブドメインを公開するプログラムです。
これにより、ポート番号やIPアドレスを使わずに自宅サーバのサービスへ簡単にアクセスできます。

## 使い方

### サーバを起動

```bash
cargo build --release

./target/release/local-subdomains
```

### mDNSクエリを送信してみよう

```bash
# サーバを起動している端末のホスト名を piyo とします
dns-sd -q hoge.piyo.local

# Timestamp      A/R  Flags  IF  Name              Type   Class  Rdata
#  17:25:55.324  Add  3      15  hoge.piyo.local.  CNAME  IN     piyo.local.
#  17:25:55.324  Add  2      15  piyo.local.       Addr   IN     192.168.1.250
```

## 豆知識

数年前に同じようなプログラムを Clojure で書いたのですが、最近 Rust で書き直しました。

## ライセンス

MIT License の下で提供されています。
