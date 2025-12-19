"""
Exit policy parsing and matching.

This module provides functionality to parse and match Tor exit policies.
Exit policies determine which destinations an exit relay will connect to.
"""


def parse_port_list(port_list: str) -> set[int]:
    """
    Parse a port list string into a set of ports.

    Args:
        port_list: Comma-separated ports and ranges (e.g., "80,443,8000-8080")

    Returns:
        Set of all ports covered by the list
    """
    ports: set[int] = set()

    if not port_list:
        return ports

    for item in port_list.split(","):
        item = item.strip()
        if not item:
            continue

        if "-" in item:
            # Port range
            parts = item.split("-")
            if len(parts) == 2:
                try:
                    start = int(parts[0])
                    end = int(parts[1])
                    ports.update(range(start, end + 1))
                except ValueError:
                    continue
        else:
            # Single port
            try:
                ports.add(int(item))
            except ValueError:
                continue

    return ports


class ExitPolicy:
    """
    Represents an exit policy summary.

    Exit policy summaries are found in:
    - Consensus "p" lines: "accept 80,443" or "reject 1-65535"
    - Microdescriptor "p" and "p6" lines

    The summary format is: <accept|reject> <portlist>
    """

    def __init__(self, policy_str: str | None) -> None:
        """
        Initialize exit policy from a policy string.

        Args:
            policy_str: Policy string like "accept 80,443" or "reject 1-65535"
        """
        self.is_accept = False
        self.ports: set[int] = set()
        self.raw = policy_str or ""

        if not policy_str:
            return

        parts = policy_str.strip().split(None, 1)
        if len(parts) < 2:
            return

        action, port_list = parts[0].lower(), parts[1]

        if action == "accept":
            self.is_accept = True
            self.ports = parse_port_list(port_list)
        elif action == "reject":
            self.is_accept = False
            self.ports = parse_port_list(port_list)

    def allows_port(self, port: int) -> bool:
        """
        Check if this policy allows connections to a specific port.

        For "accept" policies: returns True if port is in the list
        For "reject" policies: returns True if port is NOT in the list

        Args:
            port: Port number to check

        Returns:
            True if the port is allowed, False otherwise
        """
        if not self.ports:
            # Empty policy - assume no exit allowed
            return False

        if self.is_accept:
            # Accept policy: port must be in the list
            return port in self.ports
        # Reject policy: port must NOT be in the list
        return port not in self.ports

    def __repr__(self) -> str:
        return f"ExitPolicy({self.raw!r})"


def check_exit_policy(policy_str: str | None, port: int) -> bool:
    """
    Convenience function to check if a policy allows a port.

    Args:
        policy_str: Policy string like "accept 80,443"
        port: Port number to check

    Returns:
        True if port is allowed, False otherwise
    """
    return ExitPolicy(policy_str).allows_port(port)
