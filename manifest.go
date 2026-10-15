package main

import _ "embed"

//go:embed assets.json
var assetManifest []byte

//go:embed payload.json
var payloadManifest []byte
