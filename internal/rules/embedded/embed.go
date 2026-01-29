package embedded

import _ "embed"

//go:embed core.yaml
var CoreYAML []byte

//go:embed credentials.yaml
var CredentialsYAML []byte
