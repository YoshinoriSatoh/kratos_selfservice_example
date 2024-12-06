# kratos example

ory kratosの使用サンプルです。

[ory document](https://www.ory.sh/docs/welcome)

[ory kratos Github](https://github.com/ory/kratos)

以下のサンプルを用意しています。
* [selfservice curl example](https://github.com/YoshinoriSatoh/github.com/YoshinoriSatoh/kratos_example/blob/main/README-SELFSERVICE-CURL.md)

## 構成
docker-compose.yaml で以下のコンテナが起動します。

| container | description |
| ---- | ---- |
| kratos | kratos本体です |
| kratos-migrate | kratos DBに対してマイグレーションを行います |
| db-kratos | kratosのDBです (PostgreSQL) |
| mailslurper | ローカル確認用のメールサーバーです |

## 起動

### docker compose
```
docker compose up
```

## エンドポイントなど

| 項目 | URL |
| ---- | ---- |
| kratos public endpoint | http://localhost:4433 |
| kratos admin endpoint | http://localhost:4434 |
| kratos DB | postgres://kratos:secret@localhost:5432/kratos |
| mailslurper console | http://localhost:4436 |


## selfservice curl example

[kartosのSelfService flow](https://www.ory.sh/docs/kratos/self-service)をcurlで再現したサンプルです。

[selfservice curl example](https://github.com/YoshinoriSatoh/github.com/YoshinoriSatoh/kratos_example/blob/main/README-SELFSERVICE-CURL.md)
