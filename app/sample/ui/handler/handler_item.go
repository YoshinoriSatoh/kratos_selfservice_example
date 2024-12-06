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

// --------------------------------------------------------------------------
// GET /item/{id}
// --------------------------------------------------------------------------
// Request parameters for handleGetItemDetail
type getItemRequestParams struct {
	ItemID int
}

// Extract parameters from http request
func newGetItemRequestParams(r *http.Request) *getItemRequestParams {
	itemID, _ := strconv.Atoi(r.PathValue("id"))
	return &getItemRequestParams{
		ItemID: itemID,
	}
}

// Return parameters that can refer in view template
func (p *getItemRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"ItemID": p.ItemID,
	}
}

func (p *Provider) handleGetItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newGetItemRequestParams(r)

	// prepare views
	itemDetailView := newView("item/detail.html").addParams(params.toViewParams())

	// render
	item := items[params.ItemID]
	itemDetailView.addParams(map[string]any{
		"Image":       item.Image,
		"Name":        item.Name,
		"Description": item.Description,
		"Price":       item.Price,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// GET /item/{id}/purchase
// --------------------------------------------------------------------------
// Request parameters for handleGetItemPurchase
type getItemPurchaseRequestParams struct {
	ItemID int
}

// Extract parameters from http request
func newGetItemPurchaseRequestParams(r *http.Request) *getItemPurchaseRequestParams {
	itemID, _ := strconv.Atoi(r.PathValue("id"))
	return &getItemPurchaseRequestParams{
		ItemID: itemID,
	}
}

// Return parameters that can refer in view template
func (p *getItemPurchaseRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"ItemID": p.ItemID,
	}
}

func (p *Provider) handleGetItemPurchase(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newGetItemRequestParams(r)

	// prepare views
	itemPurchaseView := newView("item/purchase.html").addParams(params.toViewParams())
	itemPurchaseConfirmView := newView("item/_purchase_confirm.html").addParams(params.toViewParams())
	itemPurchaseWithoutAuthView := newView("item/_purchase_without_auth.html").addParams(params.toViewParams())

	// render
	item := items[params.ItemID]
	viewParams := map[string]any{
		"Image":       item.Image,
		"Name":        item.Name,
		"Description": item.Description,
		"Price":       pkgVars.printer.Sprintf("%d", item.Price),
	}
	if isAuthenticated(session) {
		if r.Header.Get("HX-Request") == "true" {
			itemPurchaseConfirmView.addParams(viewParams).render(w, r, session)
		} else {
			itemPurchaseView.addParams(viewParams).render(w, r, session)
		}
	} else {
		itemPurchaseWithoutAuthView.addParams(viewParams).render(w, r, session)
	}
}

// --------------------------------------------------------------------------
// POST /item/{id}/purchase
// --------------------------------------------------------------------------
// Request parameters for handlePostItemPurchase
type postItemPurchaseRequestParams struct {
	ItemID int
}

// Extract parameters from http request
func newPostItemPurchaseRequestParams(r *http.Request) *postItemPurchaseRequestParams {
	itemID, _ := strconv.Atoi(r.PathValue("id"))
	return &postItemPurchaseRequestParams{
		ItemID: itemID,
	}
}

// Return parameters that can refer in view template
func (p *postItemPurchaseRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"ItemID": p.ItemID,
	}
}

func (p *Provider) handlePostItemPurchase(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newPostItemPurchaseRequestParams(r)

	// prepare views
	itemPurchaseCompleteView := newView("item/_purchase_complete.html").addParams(params.toViewParams())

	time.Sleep(3 * time.Second)

	// render
	item := items[params.ItemID]
	itemPurchaseCompleteView.addParams(map[string]any{
		"Image":       item.Image,
		"Name":        item.Name,
		"Description": item.Description,
		"Price":       item.Price,
	}).render(w, r, session)
}
