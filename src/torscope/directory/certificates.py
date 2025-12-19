"""
Key certificate parsing.

This module provides functionality to parse Tor authority key certificates.
"""

from datetime import UTC, datetime

from torscope.directory.models import KeyCertificate


class KeyCertificateParser:
    """Parser for Tor authority key certificates."""

    @staticmethod
    def parse(content: bytes) -> list[KeyCertificate]:
        """
        Parse key certificates from raw bytes.

        Args:
            content: Raw certificate data (may contain multiple certificates)

        Returns:
            List of parsed KeyCertificate objects
        """
        text = content.decode("utf-8", errors="replace")
        certificates: list[KeyCertificate] = []

        # Split into individual certificates
        cert_texts = text.split("dir-key-certificate-version")
        for cert_text in cert_texts[1:]:  # Skip empty first element
            cert_text = "dir-key-certificate-version" + cert_text
            cert = KeyCertificateParser._parse_single(cert_text)
            if cert:
                certificates.append(cert)

        return certificates

    @staticmethod
    def _parse_single(cert_text: str) -> KeyCertificate | None:
        """Parse a single key certificate."""
        lines = cert_text.split("\n")

        version = 3
        fingerprint = ""
        published = datetime.now(UTC)
        expires = datetime.now(UTC)
        identity_key = ""
        signing_key = ""
        address: str | None = None
        crosscert: str | None = None
        certification: str | None = None

        i = 0
        while i < len(lines):
            line = lines[i].strip()

            if not line:
                i += 1
                continue

            if line.startswith("dir-key-certificate-version"):
                parts = line.split()
                if len(parts) >= 2:
                    version = int(parts[1])

            elif line.startswith("fingerprint"):
                parts = line.split()
                if len(parts) >= 2:
                    fingerprint = parts[1].upper()

            elif line.startswith("dir-key-published"):
                parts = line.split(maxsplit=1)
                if len(parts) >= 2:
                    published = KeyCertificateParser._parse_datetime(parts[1])

            elif line.startswith("dir-key-expires"):
                parts = line.split(maxsplit=1)
                if len(parts) >= 2:
                    expires = KeyCertificateParser._parse_datetime(parts[1])

            elif line.startswith("dir-address"):
                parts = line.split()
                if len(parts) >= 2:
                    address = parts[1]

            elif line.startswith("dir-identity-key"):
                # Read PEM key block
                i += 1
                key_lines = []
                while i < len(lines) and not lines[i].startswith("-----END"):
                    key_lines.append(lines[i])
                    i += 1
                if i < len(lines):
                    key_lines.append(lines[i])  # Include END line
                identity_key = "\n".join(key_lines)

            elif line.startswith("dir-signing-key"):
                # Read PEM key block
                i += 1
                key_lines = []
                while i < len(lines) and not lines[i].startswith("-----END"):
                    key_lines.append(lines[i])
                    i += 1
                if i < len(lines):
                    key_lines.append(lines[i])  # Include END line
                signing_key = "\n".join(key_lines)

            elif line.startswith("dir-key-crosscert"):
                # Read signature block
                i += 1
                sig_lines = []
                while i < len(lines) and not lines[i].startswith("-----END"):
                    sig_lines.append(lines[i])
                    i += 1
                if i < len(lines):
                    sig_lines.append(lines[i])
                crosscert = "\n".join(sig_lines)

            elif line.startswith("dir-key-certification"):
                # Read signature block
                i += 1
                sig_lines = []
                while i < len(lines) and not lines[i].startswith("-----END"):
                    sig_lines.append(lines[i])
                    i += 1
                if i < len(lines):
                    sig_lines.append(lines[i])
                certification = "\n".join(sig_lines)

            i += 1

        # Validate required fields
        if not fingerprint or not identity_key or not signing_key:
            return None

        return KeyCertificate(
            version=version,
            fingerprint=fingerprint,
            published=published,
            expires=expires,
            identity_key=identity_key,
            signing_key=signing_key,
            address=address,
            dir_key_crosscert=crosscert,
            dir_key_certification=certification,
            raw_certificate=cert_text,
        )

    @staticmethod
    def _parse_datetime(date_str: str) -> datetime:
        """Parse datetime from certificate format (YYYY-MM-DD HH:MM:SS)."""
        try:
            return datetime.strptime(date_str.strip(), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return datetime.now(UTC)
