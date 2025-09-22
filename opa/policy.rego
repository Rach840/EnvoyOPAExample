package envoy.authz

import input.attributes.request.http as http

# По умолчанию запрет
default allow := false


claims := payload if {
    io.jwt.verify_hs256(token, "secret")
    [_, payload, _] := io.jwt.decode(token)
}

token := t if {
    v := input.attributes.request.http.headers.authorization
    startswith(v, "Bearer ")
    t := substring(v, count("Bearer "), -1)
}



# Индекс ролей из data.users (массив объектов {name, role})
role_index[k] := v if {
  some i
  data.users[i]
  k := data.users[i].name
  v := data.users[i].role
}

current_role := role if {
  n := claims.name
  n != ""
  role := role_index[n]
}

is_admin if { current_role == "admin" }
is_super if { current_role == "super_admin" }
is_guest if { current_role == "guest" }


# Публичное чтение
allow if {
  http.method == "GET"
  glob.match("/public/*", ["/"], http.path)
}

# Гость читает /people/*
allow if {
  is_admin
  http.method == "GET"
  glob.match("/people/*", ["/"], http.path)
}

# Супер Пользователи — везде
allow if { is_super }



########################
# Сборка ответа для opa-envoy
########################

allow_req_headers["x-user"] := claims.name       if { allow; claims.name != "" }

allow_resp_headers["x-authz-by"] := "opa test version for orion" if { allow }

deny_headers["content-type"] := "text/plain; charset=utf-8" if { not allow }
deny_headers["x-authz-by"]   := "opa test version for orion"                        if { not allow }

headers_out := allow_req_headers if { allow }
headers_out := deny_headers      if { not allow }

# Статус и тело
status := 200 if { allow }
status := 403 if { not allow }

# TODO прописать добавления в body причины отказа

result := {
  "allowed": allow,
  "headers": headers_out,
  "http_status": status,
}
