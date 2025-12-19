#!/usr/bin/env python3
"""
Simple AlienVault OTX MCP Server - Pull threat intelligence from AlienVault Open Threat Exchange
"""
import os
import sys
import logging
from datetime import datetime, timezone, timedelta
import httpx
from mcp.server.fastmcp import FastMCP

# Configure logging to stderr
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger("alienvault-server")

# Initialize MCP server - NO PROMPT PARAMETER!
mcp = FastMCP("alienvault")

# Configuration
API_TOKEN = os.environ.get("ALIENVAULT_API_KEY", "")
BASE_URL = "https://otx.alienvault.com/api/v1"
DEFAULT_LIMIT = 20

# === UTILITY FUNCTIONS ===
def format_indicator(indicator):
    """Format a single indicator for display."""
    indicator_type = indicator.get("type", "Unknown")
    indicator_value = indicator.get("indicator", "N/A")
    description = indicator.get("description", "No description")
    title = indicator.get("title", "")
    
    result = f"  • [{indicator_type}] {indicator_value}"
    if title:
        result += f" - {title}"
    if description and description != "No description":
        result += f"\n    Description: {description}"
    return result

def format_pulse(pulse):
    """Format a pulse for display."""
    lines = []
    lines.append(f"📍 **{pulse.get('name', 'Unnamed Pulse')}**")
    lines.append(f"   ID: {pulse.get('id', 'N/A')}")
    lines.append(f"   Author: {pulse.get('author_name', 'Unknown')}")
    lines.append(f"   Created: {pulse.get('created', 'Unknown')}")
    lines.append(f"   Modified: {pulse.get('modified', 'Unknown')}")
    lines.append(f"   TLP: {pulse.get('TLP', 'white').upper()}")
    
    if pulse.get('description'):
        lines.append(f"   Description: {pulse.get('description')}")
    
    if pulse.get('tags'):
        lines.append(f"   Tags: {', '.join(pulse.get('tags', []))}")
    
    if pulse.get('targeted_countries'):
        lines.append(f"   Targeted Countries: {', '.join(pulse.get('targeted_countries', []))}")
    
    if pulse.get('industries'):
        lines.append(f"   Industries: {', '.join(pulse.get('industries', []))}")
    
    if pulse.get('adversary'):
        lines.append(f"   Adversary: {pulse.get('adversary')}")
    
    indicators = pulse.get('indicators', [])
    if indicators:
        lines.append(f"\n   Indicators ({len(indicators)} total):")
        # Show first 10 indicators
        for indicator in indicators[:10]:
            lines.append(format_indicator(indicator))
        if len(indicators) > 10:
            lines.append(f"   ... and {len(indicators) - 10} more indicators")
    
    if pulse.get('references'):
        lines.append(f"\n   References:")
        for ref in pulse.get('references', []):
            lines.append(f"   - {ref}")
    
    return "\n".join(lines)

# === MCP TOOLS ===

@mcp.tool()
async def get_subscribed_pulses(limit: str = "20", page: str = "1", modified_since: str = "") -> str:
    """Get all subscribed threat intelligence pulses from AlienVault OTX with optional limit and pagination."""
    logger.info(f"Fetching subscribed pulses - limit: {limit}, page: {page}")
    
    if not API_TOKEN.strip():
        return "❌ Error: ALIENVAULT_API_KEY not configured. Please set your API key."
    
    try:
        limit_int = int(limit) if limit.strip() else DEFAULT_LIMIT
        page_int = int(page) if page.strip() else 1
        
        url = f"{BASE_URL}/pulses/subscribed"
        params = {
            "limit": limit_int,
            "page": page_int
        }
        
        if modified_since.strip():
            params["modified_since"] = modified_since
        
        headers = {
            "X-OTX-API-KEY": API_TOKEN
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
        
        total_count = data.get("count", 0)
        pulses = data.get("results", [])
        
        if not pulses:
            return "📊 No subscribed pulses found. Make sure you have subscribed to pulses in your OTX account."
        
        result_lines = [
            f"📊 **Subscribed Threat Intelligence Pulses**",
            f"Total Pulses: {total_count}",
            f"Page {page_int} (showing {len(pulses)} pulses)",
            "=" * 60
        ]
        
        for pulse in pulses:
            result_lines.append("")
            result_lines.append(format_pulse(pulse))
            result_lines.append("-" * 60)
        
        # Add pagination info
        if data.get("next"):
            result_lines.append(f"\n💡 Use page='{page_int + 1}' to see more pulses")
        
        return "\n".join(result_lines)
        
    except ValueError as e:
        return f"❌ Error: Invalid parameter value - {str(e)}"
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            return "❌ Error: Invalid API key or unauthorized access"
        elif e.response.status_code == 404:
            return "❌ Error: No subscribed pulses found"
        else:
            return f"❌ API Error: {e.response.status_code} - {e.response.text}"
    except Exception as e:
        logger.error(f"Error fetching pulses: {e}")
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def get_recent_pulses(days: str = "7") -> str:
    """Get recently modified threat intelligence pulses from the last N days."""
    logger.info(f"Fetching pulses from last {days} days")
    
    if not API_TOKEN.strip():
        return "❌ Error: ALIENVAULT_API_KEY not configured. Please set your API key."
    
    try:
        days_int = int(days) if days.strip() else 7
        
        # Calculate modified_since date
        since_date = datetime.now(timezone.utc) - timedelta(days=days_int)
        modified_since = since_date.strftime("%Y-%m-%d")
        
        url = f"{BASE_URL}/pulses/subscribed"
        params = {
            "modified_since": modified_since,
            "limit": 50
        }
        
        headers = {
            "X-OTX-API-KEY": API_TOKEN
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
        
        pulses = data.get("results", [])
        
        if not pulses:
            return f"📊 No pulses modified in the last {days_int} days"
        
        result_lines = [
            f"📊 **Recent Threat Intelligence (Last {days_int} Days)**",
            f"Found {len(pulses)} recently modified pulses",
            f"Since: {modified_since}",
            "=" * 60
        ]
        
        for pulse in pulses:
            result_lines.append("")
            result_lines.append(format_pulse(pulse))
            result_lines.append("-" * 60)
        
        return "\n".join(result_lines)
        
    except ValueError:
        return f"❌ Error: Invalid days value: {days}"
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            return "❌ Error: Invalid API key or unauthorized access"
        else:
            return f"❌ API Error: {e.response.status_code}"
    except Exception as e:
        logger.error(f"Error fetching recent pulses: {e}")
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def get_pulse_details(pulse_id: str = "") -> str:
    """Get detailed information about a specific threat intelligence pulse by ID."""
    logger.info(f"Fetching pulse details for ID: {pulse_id}")
    
    if not API_TOKEN.strip():
        return "❌ Error: ALIENVAULT_API_KEY not configured. Please set your API key."
    
    if not pulse_id.strip():
        return "❌ Error: Pulse ID is required"
    
    try:
        url = f"{BASE_URL}/pulses/{pulse_id}"
        headers = {
            "X-OTX-API-KEY": API_TOKEN
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            pulse = response.json()
        
        result_lines = [
            f"📍 **Pulse Details**",
            "=" * 60,
            format_pulse(pulse)
        ]
        
        return "\n".join(result_lines)
        
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            return "❌ Error: Invalid API key or unauthorized access"
        elif e.response.status_code == 404:
            return f"❌ Error: Pulse not found with ID: {pulse_id}"
        else:
            return f"❌ API Error: {e.response.status_code}"
    except Exception as e:
        logger.error(f"Error fetching pulse details: {e}")
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def search_pulses(query: str = "") -> str:
    """Search for threat intelligence pulses by keyword or term."""
    logger.info(f"Searching pulses with query: {query}")
    
    if not API_TOKEN.strip():
        return "❌ Error: ALIENVAULT_API_KEY not configured. Please set your API key."
    
    if not query.strip():
        return "❌ Error: Search query is required"
    
    try:
        url = f"{BASE_URL}/search/pulses"
        params = {
            "q": query,
            "limit": 20
        }
        headers = {
            "X-OTX-API-KEY": API_TOKEN
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
        
        pulses = data.get("results", [])
        total_count = data.get("count", 0)
        
        if not pulses:
            return f"🔍 No pulses found matching: {query}"
        
        result_lines = [
            f"🔍 **Search Results for: {query}**",
            f"Found {total_count} matching pulses (showing first {len(pulses)})",
            "=" * 60
        ]
        
        for pulse in pulses:
            result_lines.append("")
            result_lines.append(format_pulse(pulse))
            result_lines.append("-" * 60)
        
        return "\n".join(result_lines)
        
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            return "❌ Error: Invalid API key or unauthorized access"
        else:
            return f"❌ API Error: {e.response.status_code}"
    except Exception as e:
        logger.error(f"Error searching pulses: {e}")
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def get_indicator_details(indicator_type: str = "", indicator_value: str = "") -> str:
    """Get threat intelligence details for a specific indicator (IPv4, domain, hostname, URL, or file hash)."""
    logger.info(f"Fetching indicator details - type: {indicator_type}, value: {indicator_value}")
    
    if not API_TOKEN.strip():
        return "❌ Error: ALIENVAULT_API_KEY not configured. Please set your API key."
    
    if not indicator_type.strip() or not indicator_value.strip():
        return "❌ Error: Both indicator_type and indicator_value are required. Types: IPv4, IPv6, domain, hostname, url, FileHash-SHA256, FileHash-SHA1, FileHash-MD5"
    
    try:
        # Map common type names to API endpoints
        type_mapping = {
            "ip": "IPv4",
            "ipv4": "IPv4",
            "ipv6": "IPv6",
            "domain": "domain",
            "hostname": "hostname",
            "url": "url",
            "sha256": "FileHash-SHA256",
            "sha1": "FileHash-SHA1",
            "md5": "FileHash-MD5",
            "file": "file"
        }
        
        api_type = type_mapping.get(indicator_type.lower(), indicator_type)
        
        url = f"{BASE_URL}/indicators/{api_type}/{indicator_value}/general"
        headers = {
            "X-OTX-API-KEY": API_TOKEN
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()
        
        result_lines = [
            f"🔍 **Indicator Analysis**",
            f"Type: {api_type}",
            f"Value: {indicator_value}",
            "=" * 60
        ]
        
        # Pulse count
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        result_lines.append(f"\n📊 Found in {pulse_count} pulses")
        
        # Related pulses
        if data.get("pulse_info", {}).get("pulses"):
            result_lines.append("\n**Related Pulses:**")
            for pulse in data.get("pulse_info", {}).get("pulses", [])[:5]:
                result_lines.append(f"  • {pulse.get('name', 'Unnamed')}")
                result_lines.append(f"    Author: {pulse.get('author_name', 'Unknown')}")
                result_lines.append(f"    Modified: {pulse.get('modified', 'Unknown')}")
                if pulse.get('description'):
                    result_lines.append(f"    Description: {pulse.get('description')[:200]}")
        
        # Validation info
        if data.get("validation"):
            validations = data.get("validation", [])
            if validations:
                result_lines.append("\n**Validation Results:**")
                for validation in validations:
                    source = validation.get("source", "Unknown")
                    name = validation.get("name", "")
                    message = validation.get("message", "")
                    result_lines.append(f"  • [{source}] {name}: {message}")
        
        # Sections available
        if data.get("sections"):
            sections = data.get("sections", [])
            result_lines.append(f"\n**Available Intelligence Sections:** {', '.join(sections)}")
        
        return "\n".join(result_lines)
        
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            return "❌ Error: Invalid API key or unauthorized access"
        elif e.response.status_code == 404:
            return f"❌ Error: Indicator not found or invalid type. Valid types: IPv4, IPv6, domain, hostname, url, FileHash-SHA256, FileHash-SHA1, FileHash-MD5"
        elif e.response.status_code == 400:
            return f"❌ Error: Invalid indicator format for type {indicator_type}"
        else:
            return f"❌ API Error: {e.response.status_code}"
    except Exception as e:
        logger.error(f"Error fetching indicator: {e}")
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def get_pulse_indicators(pulse_id: str = "", indicator_types: str = "") -> str:
    """Get all indicators from a specific pulse, optionally filtered by type (comma-separated: IPv4,domain,url)."""
    logger.info(f"Fetching indicators for pulse: {pulse_id}")
    
    if not API_TOKEN.strip():
        return "❌ Error: ALIENVAULT_API_KEY not configured. Please set your API key."
    
    if not pulse_id.strip():
        return "❌ Error: Pulse ID is required"
    
    try:
        url = f"{BASE_URL}/pulses/{pulse_id}/indicators"
        headers = {
            "X-OTX-API-KEY": API_TOKEN
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()
        
        indicators = data.get("indicators", [])
        
        # Filter by type if specified
        if indicator_types.strip():
            filter_types = [t.strip().lower() for t in indicator_types.split(",")]
            indicators = [i for i in indicators if i.get("type", "").lower() in filter_types]
        
        if not indicators:
            return f"📊 No indicators found for pulse {pulse_id}"
        
        # Group indicators by type
        by_type = {}
        for indicator in indicators:
            itype = indicator.get("type", "Unknown")
            if itype not in by_type:
                by_type[itype] = []
            by_type[itype].append(indicator)
        
        result_lines = [
            f"📊 **Pulse Indicators**",
            f"Pulse ID: {pulse_id}",
            f"Total Indicators: {len(indicators)}",
            "=" * 60
        ]
        
        for itype, items in by_type.items():
            result_lines.append(f"\n**{itype} ({len(items)} items):**")
            for item in items[:20]:  # Show first 20 of each type
                value = item.get("indicator", "N/A")
                title = item.get("title", "")
                desc = item.get("description", "")
                
                line = f"  • {value}"
                if title:
                    line += f" - {title}"
                result_lines.append(line)
                
                if desc and desc != title:
                    result_lines.append(f"    {desc[:100]}")
            
            if len(items) > 20:
                result_lines.append(f"  ... and {len(items) - 20} more {itype} indicators")
        
        return "\n".join(result_lines)
        
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            return "❌ Error: Invalid API key or unauthorized access"
        elif e.response.status_code == 404:
            return f"❌ Error: Pulse not found with ID: {pulse_id}"
        else:
            return f"❌ API Error: {e.response.status_code}"
    except Exception as e:
        logger.error(f"Error fetching indicators: {e}")
        return f"❌ Error: {str(e)}"

# === SERVER STARTUP ===
if __name__ == "__main__":
    logger.info("Starting AlienVault OTX MCP server...")
    
    if not API_TOKEN:
        logger.warning("ALIENVAULT_API_KEY not set - server will start but API calls will fail")
    else:
        logger.info("API key configured - ready to fetch threat intelligence")
    
    try:
        mcp.run(transport='stdio')
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)