MAGEN_LOGGING_LEVEL = """
{
  "level": "CRITICAL"
}"""

MAGEN_LOGGING_LEVEL_FAIL = """
{
  "level": 487
}"""

MAGEN_SINGLE_ASSET_FINANCE_POST = """
{
  "asset": [
    {
      "name": "finance doc",
      "resource_group": "roadmap",
      "resource_id": 3,
      "client_uuid": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
      "host": "sjc-repenno-nitro10.cisco.com",
      "download_url": "http:///tmp/test_up.txt"
    }
  ]
}"""


MAGEN_METADATA_TEST = """
{
    "asset_id": "c902535b-d663-4123-8c00-dc3f3349c5d0",
    "domain": "ps.box.com",
    "enc_asset_hash": "031edd7d41651593c5fe5c006fa5752b37fddff7bc4e843aa6af0c950f4b9406",
    "file_size": 14,
    "iv": null,
    "revision": 3,
    "timestamp": "2017-11-05 23:12:28.187745+00:00",
    "version": 2
}
"""

MAGEN_SINGLE_ASSET_FINANCE_POST_KEYERROR = """
{

      "name": "finance doc",
      "resource_group": "roadmap",
      "resource_id": 3,
      "client_uuid": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
      "host": "sjc-repenno-nitro10.cisco.com"

}"""

MAGEN_SINGLE_ASSET_FINANCE_POST_BADREQUEST = """
{
  "asset": [
    {
      "name": "finance doc",
      "resource_group": "roadmap",
      "resource_id": a
      "client_uuid": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
      "host": "sjc-repenno-nitro10.cisco.com",
      "download_url": "http:///tmp/test_up.txt"
    }
  ]
}
"""


MAGEN_SINGLE_ASSET_FINANCE_POST_INDEXERROR = """
{
  "asset": []
}"""

MAGEN_SINGLE_ASSET_FINANCE_POST_RESP = """
{
  "response": {
    "asset": {
      "client_uuid": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
      "creation_timestamp": "2016-09-01 21:22:13.053688+00:00",
      "host": "sjc-repenno-nitro10.cisco.com",
      "name": "finance doc",
      "resource_group": "roadmap",
      "resource_id": 3,
      "uuid": "74c1c6ff-c266-43a6-9d14-82dca05cb6df",
      "version": 1
    },
    "cause": "Created",
    "success": true
  },
  "status": 201,
  "title": "Create Asset"
}"""

MAGEN_SINGLE_ASSET_FINANCE_PUT = """
{
  "asset": [
    {
      "client_uuid": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
      "creation_timestamp": "2016-09-01 21:22:13.053688+00:00",
      "host": "sjc-repenno-nitro10.cisco.com",
      "name": "finance doc",
      "resource_group": "earnings",
      "resource_id": 2,
      "uuid": "74c1c6ff-c266-43a6-9d14-82dca05cb6df",
      "version": 1
    }
  ]
}"""

MAGEN_SINGLE_ASSET_FINANCE_GET_RESP = """
{
  "response": {
    "asset": [
      {
        "client_uuid": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
        "creation_timestamp": "2016-09-01T21:22:13.053000+00:00",
        "host": "sjc-repenno-nitro10.cisco.com",
        "name": "finance doc",
        "resource_group": "earnings",
        "resource_id": 2,
        "uuid": "1c43ae97-ce17-43cc-a90e-8733928ebb69",
        "version": 1
      }
    ],
    "cause": "Asset found",
    "success": true
  },
  "status": 200,
  "title": "Get Asset"
}"""

MAGEN_INGESTION_URLS_RESP_DICT = """{
  "response": {
    "active_urls": {
      "asset_url": "http://localhost:5020/magen/ingestion/v1/assets/asset/",
      "assets_url": "http://localhost:5020/magen/ingestion/v1/assets/",
      "single_asset_url": "http://localhost:5020/magen/ingestion/v1/assets/asset/{}/"
    },
    "source": "Ingestion"
  },
  "status": 200,
  "title": "Get Active Urls"
}"""

# download_url is filled by the running code as appropriate

MAGEN_INGESTION_POST_WITH_EMPTY_DOWNLOAD_URL = """
{
    "asset": [
        {
            "name": "finance doc",
            "resource_group": "roadmap",
            "resource_id": 3,
            "client_uuid": "<client_id>",
            "host": "sjc-repenno-nitro10.cisco.com",
            "download_url": ""
        }
    ]
}
"""

MAGEN_INGESTION_POST_WITH_FILE_DOWNLOAD_URL = """
{
    "asset": [
        {
            "name": "finance doc",
            "resource_group": "roadmap",
            "resource_id": 3,
            "client_uuid": "<client_id>",
            "host": "sjc-repenno-nitro10.cisco.com",
            "download_url": "http:///tmp/test_up.txt"
        }
    ]
}
"""