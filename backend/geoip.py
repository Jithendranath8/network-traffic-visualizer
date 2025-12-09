"""
GeoIP Lookup - IP to geographic location mapping using MaxMind GeoIP2
"""
from __future__ import annotations
import ipaddress
import os
import logging
from typing import Optional, Dict
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False
    logger.warning("geoip2 not installed. Install with: pip install geoip2")


@dataclass
class GeoIPInfo:
    """Geographic information for an IP address"""
    ip: str
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "ip": self.ip,
            "country": self.country,
            "city": self.city,
            "latitude": self.latitude,
            "longitude": self.longitude,
        }


class GeoIPLookup:
    """GeoIP lookup using MaxMind GeoIP2 database"""
    
    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize GeoIP lookup
        
        Args:
            db_path: Path to MaxMind GeoLite2-City.mmdb file
                    If None, looks for it in common locations
        """
        self._cache: Dict[str, GeoIPInfo] = {}
        self.reader = None
        self._init_database(db_path)
    
    def _init_database(self, db_path: Optional[str]):
        """Initialize MaxMind database"""
        if not GEOIP2_AVAILABLE:
            logger.error("geoip2 library not available. GeoIP lookup will return None.")
            return
        
        # Try to find database file
        if db_path is None:
            # Check common locations
            possible_paths = [
                "GeoLite2-City.mmdb",
                "/usr/share/GeoIP/GeoLite2-City.mmdb",
                "/var/lib/GeoIP/GeoLite2-City.mmdb",
                os.path.join(os.path.dirname(__file__), "..", "GeoLite2-City.mmdb"),
                os.path.expanduser("~/GeoLite2-City.mmdb"),
            ]
            
            for path in possible_paths:
                if os.path.exists(path):
                    db_path = path
                    break
        
        if db_path and os.path.exists(db_path):
            try:
                self.reader = geoip2.database.Reader(db_path)
                logger.info(f"Loaded MaxMind GeoIP database: {db_path}")
            except Exception as e:
                logger.error(f"Failed to load GeoIP database {db_path}: {e}")
                self.reader = None
        else:
            logger.warning(
                "MaxMind GeoLite2-City.mmdb not found. "
                "Download from: https://dev.maxmind.com/geoip/geoip2/geolite2/"
                "GeoIP lookup will return None for public IPs."
            )
            self.reader = None
    
    def lookup(self, ip: str) -> GeoIPInfo:
        """
        Lookup geographic information for an IP address
        
        Args:
            ip: IP address string
        
        Returns:
            GeoIPInfo object
        """
        # Check cache
        if ip in self._cache:
            return self._cache[ip]
        
        # Check if private/local IP
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                info = GeoIPInfo(ip, None, None, None, None)
                self._cache[ip] = info
                return info
        except ValueError:
            # Invalid IP
            info = GeoIPInfo(ip, None, None, None, None)
            self._cache[ip] = info
            return info
        
        # Lookup in MaxMind database
        if self.reader:
            try:
                response = self.reader.city(ip)
                info = GeoIPInfo(
                    ip=ip,
                    country=response.country.iso_code or None,
                    city=response.city.name or None,
                    latitude=response.location.latitude or None,
                    longitude=response.location.longitude or None,
                )
                self._cache[ip] = info
                return info
            except geoip2.errors.AddressNotFoundError:
                # IP not in database
                info = GeoIPInfo(ip, None, None, None, None)
                self._cache[ip] = info
                return info
            except Exception as e:
                logger.error(f"GeoIP lookup error for {ip}: {e}")
                info = GeoIPInfo(ip, None, None, None, None)
                self._cache[ip] = info
                return info
        else:
            # No database available
            info = GeoIPInfo(ip, None, None, None, None)
            self._cache[ip] = info
            return info
    
    def batch_lookup(self, ips: list[str]) -> Dict[str, GeoIPInfo]:
        """Lookup multiple IPs at once"""
        return {ip: self.lookup(ip) for ip in ips}
    
    def __del__(self):
        """Cleanup database reader"""
        if self.reader:
            try:
                self.reader.close()
            except:
                pass