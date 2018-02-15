package httpapi.authz

users = [{"alice": 1}, {"bob": 2}]

# HTTP API request
import input as http_api

default allow = false

# Allow single user
allow {
   http_api.method = "GET"
   user = users[http_api.user]
   # http_api.path = ["magen", "ingestion", "v2", "assets", "asset"]
}

