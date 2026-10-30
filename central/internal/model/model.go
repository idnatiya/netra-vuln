// Package model holds request and response types. Admin API responses are
// wrapped in WebResponse; agent API responses are the pkg/wire types as-is,
// because the agent decodes them strictly.
package model

type WebResponse[T any] struct {
	Data   T             `json:"data"`
	Paging *PageMetadata `json:"paging,omitempty"`
	Errors string        `json:"errors,omitempty"`
}

type PageMetadata struct {
	Page      int   `json:"page"`
	Size      int   `json:"size"`
	TotalItem int64 `json:"total_item"`
	TotalPage int64 `json:"total_page"`
}

// CountResponse reports how many rows an action changed.
type CountResponse struct {
	Count int `json:"count"`
}
