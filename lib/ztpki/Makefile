.PHONY: gen
gen:
	curl -sSf https://ztpki.venafi.com/api/v2/swagger/swagger.json | jq -S > swagger.json
	go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest -config codegen.yaml swagger.json
