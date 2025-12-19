# AlienVault OTX MCP Server - Implementation Guide

## Overview

This MCP server integrates with AlienVault Open Threat Exchange (OTX) to provide threat intelligence capabilities. It allows querying subscribed pulses, searching for threats, and analyzing indicators of compromise.

## API Integration Details

### Base Configuration
- **API Endpoint**: `https://otx.alienvault.com/api/v1`
- **Authentication**: API key via `X-OTX-API-KEY` header
- **Rate Limit**: 10,000 requests/hour
- **Timeout**: 30 seconds per request

### Available Endpoints Used

1. **Subscribed Pulses**: `/pulses/subscribed`
   - Pagination: `limit` and `page` parameters
   - Filtering: `modified_since` for date filtering
   
2. **Pulse Details**: `/pulses/{pulse_id}`
   - Returns complete pulse information
   
3. **Pulse Indicators**: `/pulses/{pulse_id}/indicators`
   - Returns all IoCs in a pulse
   
4. **Search**: `/search/pulses`
   - Query parameter `q` for keyword search
   
5. **Indicator Analysis**: `/indicators/{type}/{value}/general`
   - Types: IPv4, IPv6, domain, hostname, url, FileHash-*

## Data Structures

### Pulse Object
```json
{
  "id": "string",
  "name": "string",
  "description": "string",
  "author_name": "string",
  "created": "datetime",
  "modified": "datetime",
  "TLP": "white|green|amber|red",
  "tags": ["array"],
  "indicators": [
    {
      "indicator": "string",
      "type": "string",
      "title": "string",
      "description": "string"
    }
  ],
  "references": ["array"],
  "targeted_countries": ["array"],
  "industries": ["array"],
  "adversary": "string"
}
```

### Indicator Types
- IPv4, IPv6
- domain, hostname
- url
- FileHash-SHA256, FileHash-SHA1, FileHash-MD5
- email
- CVE
- YARA

## Implementation Considerations

### Error Handling
- 401: Invalid API key
- 404: Resource not found
- 429: Rate limit exceeded
- 500: Server errors

All errors are caught and returned with user-friendly messages.

### Performance Optimization
- Pagination for large datasets
- Limited display of indicators (first 10-20)
- Async HTTP calls with httpx
- 30-second timeout per request

### Security Best Practices
- API key stored in Docker secrets
- No logging of sensitive data
- HTTPS-only communication
- Input validation on all parameters

## Tool Descriptions

### get_subscribed_pulses
Retrieves pulses the user is subscribed to. Essential for daily threat intelligence review.

### get_recent_pulses
Filters pulses by modification date. Useful for catching up on recent threats.

### get_pulse_details
Deep dive into a specific pulse. Used when investigating particular threats.

### search_pulses
Keyword search across all OTX pulses. Critical for researching specific threat actors or campaigns.

### get_indicator_details
Reputation check for specific IoCs. Core functionality for incident response.

### get_pulse_indicators
Extracts IoCs from pulses for integration with security tools.

## Usage Patterns

### Daily Threat Review
```
1. get_recent_pulses(days="1")
2. get_pulse_details(pulse_id="...")
3. get_pulse_indicators(pulse_id="...")
```

### Incident Investigation
```
1. get_indicator_details(type="domain", value="suspicious.com")
2. search_pulses(query="ransomware")
3. get_pulse_indicators(pulse_id="...", indicator_types="FileHash-SHA256")
```

### Threat Hunting
```
1. search_pulses(query="APT29")
2. get_pulse_details(pulse_id="...")
3. get_pulse_indicators(pulse_id="...", indicator_types="IPv4,domain")
```

## Extending the Server

### Adding New Tools

Example: Subscribe to a pulse
```python
@mcp.tool()
async def subscribe_pulse(pulse_id: str = "") -> str:
    """Subscribe to a threat intelligence pulse."""
    url = f"{BASE_URL}/pulses/{pulse_id}/subscribe"
    # Implementation
```

### Adding Caching
Consider implementing Redis caching for frequently accessed pulses to reduce API calls.

### Webhook Integration
AlienVault OTX supports webhooks for real-time updates. Could extend server to handle push notifications.

## Maintenance Notes

- Monitor API rate limits
- Update indicator type mappings as OTX adds new types
- Check for API version changes
- Review pulse subscription health

## Testing Checklist

- [ ] API key validation
- [ ] Pulse retrieval with pagination
- [ ] Search functionality
- [ ] Indicator analysis for all types
- [ ] Error handling for all HTTP status codes
- [ ] Rate limit handling
- [ ] Empty result handling

## Support Resources

- OTX API Docs: https://otx.alienvault.com/api
- OTX Python SDK: https://github.com/AlienVault-OTX/OTX-Python-SDK
- Community Forum: https://otx.alienvault.com/forums