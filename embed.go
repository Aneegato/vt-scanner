package main

import "embed"

//go:embed web/templates/*.tmpl web/static/*
var embedFS embed.FS
