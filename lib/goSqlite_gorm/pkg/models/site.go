package models

import "gorm.io/gorm"

// Domain
type DomainSite struct {
	gorm.Model
	Title string `json:"title"`
	Url   string `json:"url"` // First page, also the root page, possibly the path after redirection
}
