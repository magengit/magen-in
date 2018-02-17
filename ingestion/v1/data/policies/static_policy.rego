package httpapi.authz

# HTTP API request
import input as http_api
import data.users

default allow = false

# Allow single user
allow {
   http_api.method = "GET"
   user = users.users[_][http_api.user]
   http_api.path = ["magen", "ingestion", "v2", "assets", "asset", asset]
   asset = http_api.asset
}

