package handler

import (
	"net/http"
	"strconv"
	"time"
)

type item struct {
	Name        string `json:"name"`
	Image       string `json:"image"`
	Description string `json:"description"`
	Link        string `json:"link"`
	Price       int    `json:"price"`
}

type handleGetItemDertailRequestPostForm struct {
	itemID int
}

func (p *Provider) handleGetItemDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	itemID, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid item id", http.StatusBadRequest)
		return
	}
	reqParams := handleGetItemDertailRequestPostForm{
		itemID: itemID,
	}

	item := items[reqParams.itemID]
	pkgVars.tmpl.ExecuteTemplate(w, "item/detail.html", viewParameters(session, r, map[string]any{
		"ItemID":      itemID,
		"Image":       item.Image,
		"Name":        item.Name,
		"Description": item.Description,
		"Price":       item.Price,
	}))
}

func (p *Provider) handleGetItemPurchase(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	itemID, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid item id", http.StatusBadRequest)
		return
	}
	reqParams := handleGetItemDertailRequestPostForm{
		itemID: itemID,
	}
	item := items[reqParams.itemID]

	localedPrice := pkgVars.printer.Sprintf("%d", item.Price)
	viewParams := map[string]any{
		"ItemID":      itemID,
		"Image":       item.Image,
		"Name":        item.Name,
		"Description": item.Description,
		"Price":       localedPrice,
	}

	if isAuthenticated(session) {
		if r.Header.Get("HX-Request") == "true" {
			pkgVars.tmpl.ExecuteTemplate(w, "item/_purchase.html", viewParameters(session, r, viewParams))
		} else {
			pkgVars.tmpl.ExecuteTemplate(w, "item/purchase.html", viewParameters(session, r, viewParams))
		}
	} else {
		pkgVars.tmpl.ExecuteTemplate(w, "item/_purchase_without_auth.html", viewParameters(session, r, viewParams))
	}
}

func (p *Provider) handlePostItemPurchase(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	itemID, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid item id", http.StatusBadRequest)
		return
	}
	reqParams := handleGetItemDertailRequestPostForm{
		itemID: itemID,
	}
	item := items[reqParams.itemID]

	time.Sleep(3 * time.Second)

	viewParams := map[string]any{
		"ItemID":      itemID,
		"Image":       item.Image,
		"Name":        item.Name,
		"Description": item.Description,
		"Price":       item.Price,
	}

	pkgVars.tmpl.ExecuteTemplate(w, "item/_purchase_complete.html", viewParameters(session, r, viewParams))
}
