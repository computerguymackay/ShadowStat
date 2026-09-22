package web

import "embed"

//go:embed static/app.css static/app.js static/vendor/uplot/*
var staticFS embed.FS
