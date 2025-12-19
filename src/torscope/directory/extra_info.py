"""
Extra-info descriptor parsing.

This module provides functionality to parse Tor extra-info descriptors,
which contain relay statistics like bandwidth history, exit traffic,
and directory request statistics.
"""

# pylint: disable=duplicate-code

import re
from datetime import UTC, datetime

from torscope.directory.models import BandwidthHistory, ExtraInfoDescriptor


class ExtraInfoParser:
    """Parser for Tor extra-info descriptors."""

    @staticmethod
    def parse(content: bytes) -> list[ExtraInfoDescriptor]:
        """
        Parse extra-info descriptors from raw bytes.

        Args:
            content: Raw descriptor bytes (may contain multiple descriptors)

        Returns:
            List of parsed ExtraInfoDescriptor objects
        """
        text = content.decode("utf-8", errors="replace")
        return ExtraInfoParser.parse_text(text)

    @staticmethod
    def parse_text(text: str) -> list[ExtraInfoDescriptor]:
        """
        Parse extra-info descriptors from text.

        Args:
            text: Descriptor text (may contain multiple descriptors)

        Returns:
            List of parsed ExtraInfoDescriptor objects
        """
        descriptors = []

        # Split into individual descriptors
        raw_descriptors = re.split(r"(?=^extra-info\s)", text, flags=re.MULTILINE)

        for raw in raw_descriptors:
            raw = raw.strip()
            if not raw or not raw.startswith("extra-info "):
                continue

            try:
                descriptor = ExtraInfoParser._parse_single(raw)
                if descriptor:
                    descriptors.append(descriptor)
            # pylint: disable-next=broad-exception-caught
            except Exception:
                continue

        return descriptors

    @staticmethod
    def _parse_single(text: str) -> ExtraInfoDescriptor | None:
        """Parse a single extra-info descriptor."""
        lines = text.split("\n")

        # Parse extra-info line (required)
        # extra-info <nickname> <fingerprint>
        if not lines[0].startswith("extra-info "):
            return None

        parts = lines[0].split()
        if len(parts) < 3:
            return None

        nickname = parts[1]
        fingerprint = parts[2].upper()

        # Initialize with defaults
        published = datetime.now(UTC)
        write_history: BandwidthHistory | None = None
        read_history: BandwidthHistory | None = None
        dirreq_write_history: BandwidthHistory | None = None
        dirreq_read_history: BandwidthHistory | None = None
        geoip_db_digest: str | None = None
        geoip6_db_digest: str | None = None
        dirreq_stats_end: datetime | None = None
        dirreq_v3_ips: dict[str, int] = {}
        dirreq_v3_reqs: dict[str, int] = {}
        dirreq_v3_resp: dict[str, int] = {}
        entry_stats_end: datetime | None = None
        entry_ips: dict[str, int] = {}
        exit_stats_end: datetime | None = None
        exit_kibibytes_written: dict[str, int] = {}
        exit_kibibytes_read: dict[str, int] = {}
        exit_streams_opened: dict[str, int] = {}
        cell_stats_end: datetime | None = None
        cell_processed_cells: list[float] = []
        cell_queued_cells: list[float] = []
        cell_time_in_queue: list[int] = []
        hidserv_stats_end: datetime | None = None
        hidserv_rend_relayed_cells: int | None = None
        hidserv_dir_onions_seen: int | None = None

        for line in lines[1:]:
            line = line.strip()

            if line.startswith("published "):
                published = ExtraInfoParser._parse_datetime(line[10:])

            elif line.startswith("write-history "):
                write_history = ExtraInfoParser._parse_history(line[14:])

            elif line.startswith("read-history "):
                read_history = ExtraInfoParser._parse_history(line[13:])

            elif line.startswith("dirreq-write-history "):
                dirreq_write_history = ExtraInfoParser._parse_history(line[21:])

            elif line.startswith("dirreq-read-history "):
                dirreq_read_history = ExtraInfoParser._parse_history(line[20:])

            elif line.startswith("geoip-db-digest "):
                geoip_db_digest = line[16:]

            elif line.startswith("geoip6-db-digest "):
                geoip6_db_digest = line[17:]

            elif line.startswith("dirreq-stats-end "):
                dirreq_stats_end = ExtraInfoParser._parse_stats_end(line[17:])

            elif line.startswith("dirreq-v3-ips "):
                dirreq_v3_ips = ExtraInfoParser._parse_key_value_pairs(line[14:])

            elif line.startswith("dirreq-v3-reqs "):
                dirreq_v3_reqs = ExtraInfoParser._parse_key_value_pairs(line[15:])

            elif line.startswith("dirreq-v3-resp "):
                dirreq_v3_resp = ExtraInfoParser._parse_key_value_pairs(line[15:])

            elif line.startswith("entry-stats-end "):
                entry_stats_end = ExtraInfoParser._parse_stats_end(line[16:])

            elif line.startswith("entry-ips "):
                entry_ips = ExtraInfoParser._parse_key_value_pairs(line[10:])

            elif line.startswith("exit-stats-end "):
                exit_stats_end = ExtraInfoParser._parse_stats_end(line[15:])

            elif line.startswith("exit-kibibytes-written "):
                exit_kibibytes_written = ExtraInfoParser._parse_key_value_pairs(line[23:])

            elif line.startswith("exit-kibibytes-read "):
                exit_kibibytes_read = ExtraInfoParser._parse_key_value_pairs(line[20:])

            elif line.startswith("exit-streams-opened "):
                exit_streams_opened = ExtraInfoParser._parse_key_value_pairs(line[20:])

            elif line.startswith("cell-stats-end "):
                cell_stats_end = ExtraInfoParser._parse_stats_end(line[15:])

            elif line.startswith("cell-processed-cells "):
                cell_processed_cells = ExtraInfoParser._parse_float_list(line[21:])

            elif line.startswith("cell-queued-cells "):
                cell_queued_cells = ExtraInfoParser._parse_float_list(line[18:])

            elif line.startswith("cell-time-in-queue "):
                cell_time_in_queue = ExtraInfoParser._parse_int_list(line[19:])

            elif line.startswith("hidserv-stats-end "):
                hidserv_stats_end = ExtraInfoParser._parse_stats_end(line[18:])

            elif line.startswith("hidserv-rend-relayed-cells "):
                hidserv_rend_relayed_cells = ExtraInfoParser._parse_obfuscated_int(line[27:])

            elif line.startswith("hidserv-dir-onions-seen "):
                hidserv_dir_onions_seen = ExtraInfoParser._parse_obfuscated_int(line[24:])

        return ExtraInfoDescriptor(
            nickname=nickname,
            fingerprint=fingerprint,
            published=published,
            write_history=write_history,
            read_history=read_history,
            dirreq_write_history=dirreq_write_history,
            dirreq_read_history=dirreq_read_history,
            geoip_db_digest=geoip_db_digest,
            geoip6_db_digest=geoip6_db_digest,
            dirreq_stats_end=dirreq_stats_end,
            dirreq_v3_ips=dirreq_v3_ips,
            dirreq_v3_reqs=dirreq_v3_reqs,
            dirreq_v3_resp=dirreq_v3_resp,
            entry_stats_end=entry_stats_end,
            entry_ips=entry_ips,
            exit_stats_end=exit_stats_end,
            exit_kibibytes_written=exit_kibibytes_written,
            exit_kibibytes_read=exit_kibibytes_read,
            exit_streams_opened=exit_streams_opened,
            cell_stats_end=cell_stats_end,
            cell_processed_cells=cell_processed_cells,
            cell_queued_cells=cell_queued_cells,
            cell_time_in_queue=cell_time_in_queue,
            hidserv_stats_end=hidserv_stats_end,
            hidserv_rend_relayed_cells=hidserv_rend_relayed_cells,
            hidserv_dir_onions_seen=hidserv_dir_onions_seen,
            raw_descriptor=text,
        )

    @staticmethod
    def _parse_datetime(dt_str: str) -> datetime:
        """Parse datetime string like '2024-01-15 12:00:00'."""
        try:
            dt = datetime.strptime(dt_str.strip(), "%Y-%m-%d %H:%M:%S")
            return dt.replace(tzinfo=UTC)
        except ValueError:
            return datetime.now(UTC)

    @staticmethod
    def _parse_stats_end(line: str) -> datetime | None:
        """Parse stats-end line like '2024-01-15 12:00:00 (86400 s)'."""
        match = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
        if match:
            return ExtraInfoParser._parse_datetime(match.group(1))
        return None

    @staticmethod
    def _parse_history(line: str) -> BandwidthHistory | None:
        """
        Parse bandwidth history line.

        Format: YYYY-MM-DD HH:MM:SS (NSEC s) NUM,NUM,...
        """
        match = re.match(
            r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \((\d+) s\)\s*(.*)",
            line,
        )
        if not match:
            return None

        timestamp = ExtraInfoParser._parse_datetime(match.group(1))
        interval_seconds = int(match.group(2))
        values_str = match.group(3)

        values: list[int] = []
        if values_str:
            for v in values_str.split(","):
                try:
                    values.append(int(v))
                except ValueError:
                    pass

        return BandwidthHistory(
            timestamp=timestamp,
            interval_seconds=interval_seconds,
            values=values,
        )

    @staticmethod
    def _parse_key_value_pairs(line: str) -> dict[str, int]:
        """
        Parse key=value pairs like 'us=100,de=50,fr=25'.
        """
        result: dict[str, int] = {}
        if not line.strip():
            return result

        for pair in line.split(","):
            if "=" in pair:
                key, value = pair.split("=", 1)
                try:
                    result[key] = int(value)
                except ValueError:
                    pass
        return result

    @staticmethod
    def _parse_float_list(line: str) -> list[float]:
        """Parse comma-separated float values."""
        result: list[float] = []
        for v in line.split(","):
            try:
                result.append(float(v))
            except ValueError:
                pass
        return result

    @staticmethod
    def _parse_int_list(line: str) -> list[int]:
        """Parse comma-separated int values."""
        result: list[int] = []
        for v in line.split(","):
            try:
                result.append(int(v))
            except ValueError:
                pass
        return result

    @staticmethod
    def _parse_obfuscated_int(line: str) -> int | None:
        """
        Parse obfuscated integer with Laplace noise.

        Format: NUM delta_f=X epsilon=Y bin_size=Z
        We just extract the main number.
        """
        parts = line.split()
        if parts:
            try:
                return int(parts[0])
            except ValueError:
                pass
        return None
