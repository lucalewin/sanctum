# sanctum

## Endpoints

```
POST /api/v1/auth/login_start
POST /api/v1/auth/login_finish
POST /api/v1/auth/logout

GET /api/v1/me

GET /api/v1/vaults
POST /api/v1/vaults
PUT /api/v1/vaults/:id
DELETE /api/v1/vaults/:id

GET /api/v1/records
POST /api/v1/records
PUT /api/v1/records/:id
DELETE /api/v1/records/:id

GET /api/v1/sync?since=<timestamp>
```
