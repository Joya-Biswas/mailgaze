"""
GeoIP lookup using MaxMind's GeoLite2-City database.

This module provides IP-to-location lookups. It lazy-loads the GeoLite2-City
database from the project root. If the database is missing or the IP is invalid,
it returns a safe default without raising an exception.

To use this, download GeoLite2-City.mmdb from:
  https://dev.maxmind.com/geoip/geolite2-city/
"""

import os
from typing import Optional


# Global variable to cache the geoip database reader
_geoip_reader = None


def _get_reader():
    """
    Lazy-load the GeoIP2 reader. Only loads the .mmdb file once.

    Returns:
        A geoip2.database.Reader object, or None if the database is not found.
    """
    global _geoip_reader

    if _geoip_reader is not None:
        return _geoip_reader

    try:
        # Look for the database in the project root
        db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "GeoLite2-City.mmdb")

        if not os.path.exists(db_path):
            # Database not found; return None gracefully
            return None

        # Import geoip2 only if we need it
        import geoip2.database

        # Open the reader and cache it globally
        _geoip_reader = geoip2.database.Reader(db_path)
        return _geoip_reader
    except ImportError:
        # geoip2 module not installed; return None gracefully
        return None
    except Exception:
        # Any other error (invalid DB file, permission, etc.); return None gracefully
        return None


def lookup_ip(ip: str) -> dict:
    """
    Look up the geographic location of an IP address.

    Args:
        ip: IPv4 or IPv6 address to look up.

    Returns:
        A dict with keys: country (str), city (str), lat (float or None), lon (float or None).
        If the IP is private, invalid, or the database is unavailable,
        returns {"country": "Unknown", "city": "Unknown", "lat": None, "lon": None}.
    """
    # Default safe return value
    default_result = {
        "country": "Unknown",
        "city": "Unknown",
        "lat": None,
        "lon": None,
    }

    if not ip or not isinstance(ip, str):
        return default_result

    # Check if IP is private (127.0.0.1, 192.168.*, 10.*, etc.)
    if is_private_ip(ip):
        return default_result

    try:
        reader = _get_reader()
        if reader is None:
            # Database not available
            return default_result

        # Perform the lookup
        response = reader.city(ip)

        # Extract country and city names
        country = response.country.name or "Unknown"
        city = response.city.name or "Unknown"

        # Extract latitude and longitude
        lat = response.location.latitude
        lon = response.location.longitude

        return {
            "country": country,
            "city": city,
            "lat": lat,
            "lon": lon,
        }
    except Exception:
        # Any lookup error (invalid IP, DB error, etc.); return default gracefully
        return default_result


def is_private_ip(ip: str) -> bool:
    """
    Check if an IP address is private (not routable on the public internet).

    Args:
        ip: IPv4 or IPv6 address to check.

    Returns:
        True if the IP is private, False otherwise.
    """
    try:
        # Use the stdlib ipaddress module for a proper check
        import ipaddress

        addr = ipaddress.ip_address(ip)
        return addr.is_private
    except (ValueError, AttributeError):
        # If parsing fails, assume it's not private
        return False
