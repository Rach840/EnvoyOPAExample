package envoy.authz

import input.attributes.request.http as http


# По умолчанию запрещаем
default allow = false

########################
# JWT (демо: HS256 "secret")
########################

token := {"valid": valid, "payload": payload} if {
	[_, encoded] := split(http_request.headers.authorization, " ")
	[valid, _, payload] := io.jwt.decode_verify(encoded, {"secret": "secret"})
}



user_by_name[user] {
    some i
    data.users[i].name == token.payload.name
    user := data.users[i].role
}

is_admin if {
  token.valid
  role_by_name[role]
  role == "admin"
}

is_guest if {
  token.valid
   role_by_name[role]
  role == "guest"
}


allow if {
  http.method == "GET"
  glob.match("/public/*", ["/"], http.path)
}


allow if {
  is_guest
  http.method == "GET"
  glob.match("/people/*", ["/"], http.path)
}


allow if { is_admin }

# 4) «Умный» отказ: POST /people, если firstname совпадает с sub (после base64url decode)
deny_reason = reason if {
  http.method == "POST"
  input.parsed_body.firstname
  token.valid
  lower(input.parsed_body.firstname) == lower(base64url.decode(token.payload.sub))
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

resp_headers["x-user"] = token.payload.sub if {
  token.valid
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
  "response_headers_to_add": {"x-authz-by": "i suck dick "},
  "http_status": status,
  "body": body,
}