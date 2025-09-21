package envoy.authz

import input.attributes.request.http as http

# По умолчанию запрещаем
default allow = false

########################
# JWT (демо: HS256 "secret")
########################

token_valid if {
  http.headers.authorization
  parts := split(http.headers.authorization, " ")
  count(parts) == 2
  parts[0] == "Bearer"
  token := parts[1]
  out := io.jwt.decode_verify(token, {"secret": "secret"})
  out[0] == true
}

token_payload = payload if {
  token_valid
  parts := split(http.headers.authorization, " ")
  tok := parts[1]
  out := io.jwt.decode_verify(tok, {"secret": "secret"})
  payload := out[2]
}

is_admin if {
  token_valid
  token_payload.role == "admin"
}

is_guest if {
  token_valid
  token_payload.role == "guest"
}

########################
# Правила доступа
########################

# 1) Публичные GET на /public/*
allow if {
  http.method == "GET"
  glob.match("/public/*", ["/"], http.path)
}

# 2) Гости могут только GET /people/*
allow if {
  is_guest
  http.method == "GET"
  glob.match("/people/*", ["/"], http.path)
}

# 3) Админы — везде
allow if { is_admin }

# 4) «Умный» отказ: POST /people, если firstname совпадает с sub (после base64url decode)
deny_reason = reason if {
  http.method == "POST"
  input.parsed_body.firstname
  token_valid
  lower(input.parsed_body.firstname) == lower(base64url.decode(token_payload.sub))
  reason := "firstname must not match your id"
}

########################
# Сборка ответа для opa-envoy
########################

# Разрешение = allow И НЕТ причины отказа
permitted if {
  allow
  not deny_reason
}

# Заголовки ответа (object rule со статичным и условным ключами)
resp_headers["x-ext-auth-allow"] = "yes"

resp_headers["x-user"] = token_payload.sub if {
  token_valid
}

# Статус/тело
status = 200 if { permitted }
status = 403 if { deny_reason }

body = "" if { permitted }
body = sprintf("Denied: %s", [deny_reason]) if { deny_reason }

# Финальный объект (ожидается плагином opa-envoy)
result = {
  "allowed": permitted,
  "headers": resp_headers,
  "response_headers_to_add": {"x-authz-by": "shit"},
  "http_status": status,
  "body": body,
}