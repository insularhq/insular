package system.log

import rego.v1

# decision logs never carry the partner's credentials (Matrix access tokens, OIDC tokens, cookies)
mask contains "/input/attributes/request/http/headers/authorization"

mask contains "/input/attributes/request/http/headers/cookie"
