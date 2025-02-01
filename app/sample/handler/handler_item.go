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

// Handler GET /item/{id}
func (p *Provider) handleGetItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// get request parameters
	reqParams := &getItemRequestParams{
		ItemID: func() int {
			itemID, _ := strconv.Atoi(r.PathValue("id"))
			return itemID
		}(),
	}

	// prepare views
	itemDetailView := newView(TPL_ITEM_DETAIL).addParams(map[string]any{
		"ItemID": reqParams.ItemID,
	})

	// get item
	item := items[reqParams.ItemID]

	// render page
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

func (p *Provider) handleGetItemPurchase(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// get request parameters
	reqParams := &getItemPurchaseRequestParams{
		ItemID: func() int {
			itemID, _ := strconv.Atoi(r.PathValue("id"))
			return itemID
		}(),
	}

	// prepare views
	itemPurchaseView := newView(TPL_ITEM_PURCHASE).addParams(map[string]any{
		"ItemID": reqParams.ItemID,
	})
	itemPurchaseConfirmView := newView(TPL_ITEM_PURCHASE_CONFIRM).addParams(map[string]any{
		"ItemID": reqParams.ItemID,
	})
	itemPurchaseWithoutAuthView := newView(TPL_ITEM_PURCHASE_WITHOUT_AUTH).addParams(map[string]any{
		"ItemID": reqParams.ItemID,
	})

	// get item
	item := items[reqParams.ItemID]

	// prepare view parameters
	viewParams := map[string]any{
		"Image":       item.Image,
		"Name":        item.Name,
		"Description": item.Description,
		"Price":       pkgVars.printer.Sprintf("%d", item.Price),
	}

	// render page
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

// Handler POST /item/{id}/purchase
func (p *Provider) handlePostItemPurchase(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// get request parameters
	reqParams := &postItemPurchaseRequestParams{
		ItemID: func() int {
			itemID, _ := strconv.Atoi(r.PathValue("id"))
			return itemID
		}(),
	}

	// prepare views
	itemPurchaseCompleteView := newView(TPL_ITEM_PURCHASE_COMPLETE).addParams(map[string]any{
		"ItemID": reqParams.ItemID,
	})

	// simulate purchase process
	time.Sleep(3 * time.Second)

	// get item
	item := items[reqParams.ItemID]

	// render page
	itemPurchaseCompleteView.addParams(map[string]any{
		"Image":       item.Image,
		"Name":        item.Name,
		"Description": item.Description,
		"Price":       item.Price,
	}).render(w, r, session)
}
