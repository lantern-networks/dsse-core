# Released grant-store compatibility fixture

Source: public `lantern-networks/dsse-core`, commit `5b36863f47d54515c1f331401bf6dfc46e0e113d`, VERSION `0.3.1`.

Production files copied unchanged except the package name (`grantstore` → `releasedv031`). This fixture deliberately keeps the old JSON decoder, validation, transaction and revocation behavior. Do not update it to make a regression pass.

SHA-256 of the original files:

- `grantstore.go`: `cbec55975da11a0f4e9d7610e702b61ddf010fb39140f6c6abd0a880b7a30272`
- `ingestion.go`: `f8c6061ca93fc2458d1c0596b29a7bf3650fe26f85ffa07e7ab4ecdfc8091d21`
- `read_refresh.go`: `a436fc9781c169c48faaa4a323e8e8ee58c09a00c92bec438a93edda5ea65768`
- `shared.go`: `8542d9c5a04b3478471d11d22bdcb728af99cbf87eed6da6cd97f97ef2839c75`

`gate.go` also retains the released `hasLiveGrantFor` predicate verbatim, wrapped in a small exported test entrypoint. This deliberately includes the released tenant-wide fallback; it is not a recommendation for new authorization behavior.
