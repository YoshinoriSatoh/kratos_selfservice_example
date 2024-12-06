package handler

import (
	"log/slog"
	"net/http"
)

var items = []item{
	{
		Name:        "Apple Watch",
		Image:       "http://localhost:3000/assets/images/apple-watch.png",
		Description: "Apple Watch Series 7 GPS, Aluminium Case, Starlight Sport. 商品概要\nApple Watch Series 8は、最新の技術とエレガントなデザインを融合させたスマートウォッチです。日常生活をサポートし、健康管理からフィットネス追跡まで、多機能なウェアラブルデバイスをお探しの方に最適です。\n\n主な機能\n\n\n 健康管理: 24時間心拍数モニタリング、心電図アプリ、血中酸素濃度測定など、先進的なヘルスケア機能が充実しています。新しい体温センサーも搭載しており、より詳細な健康データが得られます。\n 運動機能: さまざまなワークアウトを自動検出し、詳細な運動データを記録します。水泳にも対応しており、耐水性能は50mです。\n 通信機能: GPS + Cellularモデルなので、iPhoneがなくても単体で通話やメッセージの送受信が可能です。便利な音声アシスタント「Siri」も搭載しています。\n 通知機能: メール、メッセージ、アプリの通知を手元で確認できます。急な連絡も見逃しません。\n バッテリー: 一回の充電で最大18時間使用可能。急速充電にも対応しています。\n 状態\n 購入後、約3ヶ月使用しましたが、新しいモデルを購入したため出品します。目立つ傷や汚れはなく、非常に良好な状態です。箱、充電器、マニュアルなどの付属品もすべて揃っています。\n 発送方法\n 丁寧に梱包し、迅速に発送いたします。送料無料でお届けします。\n\n 価格\n お得な価格で提供していますが、値下げ交渉にも応じますので、お気軽にご相談ください。",
		Link:        "/item/1",
		Price:       1000,
	},
	{
		Name:        "Apple Watch",
		Image:       "http://localhost:3000/assets/images/apple-watch.png",
		Description: "Apple Watch Series 7 GPS, Aluminium Case, Starlight Sport. 商品概要\nApple Watch Series 8は、最新の技術とエレガントなデザインを融合させたスマートウォッチです。日常生活をサポートし、健康管理からフィットネス追跡まで、多機能なウェアラブルデバイスをお探しの方に最適です。\n\n主な機能\n\n\n 健康管理: 24時間心拍数モニタリング、心電図アプリ、血中酸素濃度測定など、先進的なヘルスケア機能が充実しています。新しい体温センサーも搭載しており、より詳細な健康データが得られます。\n 運動機能: さまざまなワークアウトを自動検出し、詳細な運動データを記録します。水泳にも対応しており、耐水性能は50mです。\n 通信機能: GPS + Cellularモデルなので、iPhoneがなくても単体で通話やメッセージの送受信が可能です。便利な音声アシスタント「Siri」も搭載しています。\n 通知機能: メール、メッセージ、アプリの通知を手元で確認できます。急な連絡も見逃しません。\n バッテリー: 一回の充電で最大18時間使用可能。急速充電にも対応しています。\n 状態\n 購入後、約3ヶ月使用しましたが、新しいモデルを購入したため出品します。目立つ傷や汚れはなく、非常に良好な状態です。箱、充電器、マニュアルなどの付属品もすべて揃っています。\n 発送方法\n 丁寧に梱包し、迅速に発送いたします。送料無料でお届けします。\n\n 価格\n お得な価格で提供していますが、値下げ交渉にも応じますので、お気軽にご相談ください。",
		Link:        "/item/1",
		Price:       1000,
	},
	{
		Name:        "Apple Watch",
		Image:       "http://localhost:3000/assets/images/apple-watch.png",
		Description: "Apple Watch Series 7 GPS, Aluminium Case, Starlight Sport",
		Link:        "/item/2",
		Price:       1000,
	},
	{
		Name:        "Apple Watch",
		Image:       "http://localhost:3000/assets/images/apple-watch.png",
		Description: "Apple Watch Series 7 GPS, Aluminium Case, Starlight Sport",
		Link:        "/item/3",
		Price:       1000,
	},
	{
		Name:        "Apple Watch",
		Image:       "http://localhost:3000/assets/images/apple-watch.png",
		Description: "Apple Watch Series 7 GPS, Aluminium Case, Starlight Sport",
		Link:        "/item/4",
		Price:       1000,
	},
	{
		Name:        "Apple Watch",
		Image:       "http://localhost:3000/assets/images/apple-watch.png",
		Description: "Apple Watch Series 7 GPS, Aluminium Case, Starlight Sport",
		Link:        "/item/5",
		Price:       1000,
	},
	{
		Name:        "Apple Watch",
		Image:       "http://localhost:3000/assets/images/apple-watch.png",
		Description: "Apple Watch Series 7 GPS, Aluminium Case, Starlight Sport",
		Link:        "/item/6",
		Price:       1000,
	},
	{
		Name:        "Apple Watch",
		Image:       "http://localhost:3000/assets/images/apple-watch.png",
		Description: "Apple Watch Series 7 GPS, Aluminium Case, Starlight Sport",
		Link:        "/item/7",
		Price:       1000,
	},
	{
		Name:        "Apple Watch",
		Image:       "http://localhost:3000/assets/images/apple-watch.png",
		Description: "Apple Watch Series 7 GPS, Aluminium Case, Starlight Sport",
		Link:        "/item/8",
		Price:       1000,
	},
}

func (p *Provider) handleGetTop(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	slog.Debug("handleGetTop", "request", r.Header["Cookie"])

	// prepare views
	topIndexView := newView("top/index.html")

	slog.Debug("", "session", session)

	// render
	topIndexView.addParams(map[string]any{
		"Items": items,
	}).render(w, r, session)
}
