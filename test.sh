#!/bin/bash

# Токены (демо)
ALICE_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiZ3Vlc3QiLCJzdWIiOiJZV3hwWTJVPSIsIm5iZiI6MTUxNDg1MTEzOSwiZXhwIjoxOTQxMDgxNTM5fQ.rN_hxMsoQzCjg6lav6mfzDlovKM9azaAjuwhjq3n9r8"
BOB_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4iLCJzdWIiOiJZbTlpIiwibmJmIjoxNTE0ODUxMTM5LCJleHAiOjE5NDEwODE1Mzl9.ek3jmNLPclafELVLTfyjtQNj0QKIEGrbhKqpwXmQ8EQ"

# 1) Публичный ресурс без токена — ОК
curl -i http://localhost:8000/public/anything

# 2) Гость читает /people/1 — ОК
curl -i -H "Authorization: Bearer $ALICE_TOKEN" http://localhost:8000/people/1

# 3) Гость POST /people — ДОЛЖНО ОТКАЗАТЬ С 403
curl -i -H "Authorization: Bearer $ALICE_TOKEN" \
  -H "content-type: application/json" \
  -d '{"firstname":"Charlie"}' \
  http://localhost:8000/people

