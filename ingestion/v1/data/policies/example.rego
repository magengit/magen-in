package opa.authz_policy

# HTTP API request
import input as http_api
import data.alice
import data.asset

default allow = false

# Allow single user
allow {
   http_api.owner = alice[owner]
   http_api.asset = alice[assets][_]
   http_api.owner = asset[owner]
   http_api.asset = asset[asset_id]
   http_api.user = asset[users][_]
   http_api.path = asset[url]
}