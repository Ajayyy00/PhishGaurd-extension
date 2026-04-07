# PhishGuard API Documentation

## Base URL

```
http://localhost:5000
```

## Endpoints

### Health Check

```
GET /health
```

**Response:**

```json
{
  "status": "healthy",
  "service": "phishguard-api"
}
```

---

### API Status

```
GET /api/status
```

**Response:**

```json
{
  "status": "operational",
  "version": "1.0.0",
  "model_loaded": false,
  "model_version": null
}
```

---

### Analyze URL

```
POST /api/analyze
```

**Request Body:**

```json
{
  "url": "https://example.com",
  "content": "optional page content"
}
```

**Response:**

```json
{
  "url": "https://example.com",
  "is_phishing": false,
  "confidence": 0.95,
  "risk_level": "low",
  "features": {},
  "explanation": "Analysis details"
}
```

---

### Batch Analyze

```
POST /api/batch
```

**Request Body:**

```json
{
  "urls": ["https://example1.com", "https://example2.com"]
}
```

**Response:**

```json
{
  "results": [
    {
      "url": "https://example1.com",
      "is_phishing": false,
      "confidence": 0.95,
      "risk_level": "low"
    }
  ]
}
```

## Error Responses

```json
{
  "error": "Error description"
}
```

**HTTP Status Codes:**

- `200` - Success
- `400` - Bad Request
- `500` - Internal Server Error
