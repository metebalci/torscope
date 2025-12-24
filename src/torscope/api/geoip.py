"""
GeoIP lookup for router location data.

Uses MaxMind GeoLite2-City database for IP to location mapping.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Default GeoIP database path (current directory)
GEOIP_DB_PATH = Path.cwd() / "GeoLite2-City.mmdb"


def find_geoip_db() -> Path | None:
    """Find GeoIP database in current directory."""
    if GEOIP_DB_PATH.exists():
        return GEOIP_DB_PATH
    return None


@dataclass
class GeoLocation:
    """Geographic location information for an IP address."""

    latitude: float
    longitude: float
    country_code: str
    country_name: str
    city: str | None = None
    accuracy_radius: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "latitude": self.latitude,
            "longitude": self.longitude,
            "country_code": self.country_code,
            "country_name": self.country_name,
            "city": self.city,
            "accuracy_radius": self.accuracy_radius,
        }


class GeoIPLookup:
    """
    GeoIP database lookup.

    Uses MaxMind GeoLite2-City database for IP geolocation.
    Falls back gracefully if database is not available.
    """

    def __init__(self, db_path: Path | str | None = None) -> None:
        """
        Initialize GeoIP lookup.

        Args:
            db_path: Path to GeoLite2-City.mmdb file.
                     If None, searches in current dir then ~/.torscope/geoip/
        """
        self._reader: Any = None
        self._available = False
        self._db_path: Path | None = None

        if db_path is None:
            db_path = find_geoip_db()
        else:
            db_path = Path(db_path)

        if db_path is not None and db_path.exists():
            try:
                import geoip2.database

                self._reader = geoip2.database.Reader(str(db_path))
                self._available = True
                self._db_path = db_path
            except ImportError:
                pass
            except Exception:  # pylint: disable=broad-exception-caught
                pass

    @property
    def available(self) -> bool:
        """Check if GeoIP database is available."""
        return self._available

    @property
    def db_path(self) -> Path | None:
        """Get the path to the loaded database."""
        return self._db_path

    def lookup(self, ip: str) -> GeoLocation | None:
        """
        Look up location for an IP address.

        Args:
            ip: IPv4 or IPv6 address

        Returns:
            GeoLocation if found, None otherwise
        """
        if not self._available or self._reader is None:
            return None

        try:
            import geoip2.errors

            response = self._reader.city(ip)
            return GeoLocation(
                latitude=response.location.latitude or 0.0,
                longitude=response.location.longitude or 0.0,
                country_code=response.country.iso_code or "XX",
                country_name=response.country.name or "Unknown",
                city=response.city.name,
                accuracy_radius=response.location.accuracy_radius,
            )
        except geoip2.errors.AddressNotFoundError:
            return None
        except Exception:  # pylint: disable=broad-exception-caught
            return None

    def close(self) -> None:
        """Close the database reader."""
        if self._reader is not None:
            self._reader.close()
            self._reader = None
            self._available = False


# Global instance
_geoip: GeoIPLookup | None = None


def get_geoip() -> GeoIPLookup:
    """Get global GeoIP lookup instance."""
    global _geoip
    if _geoip is None:
        _geoip = GeoIPLookup()
    return _geoip


def init_geoip(db_path: Path | str | None = None) -> GeoIPLookup:
    """Initialize global GeoIP lookup with custom path."""
    global _geoip
    _geoip = GeoIPLookup(db_path)
    return _geoip
