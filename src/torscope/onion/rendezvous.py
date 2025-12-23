"""
Hidden service rendezvous protocol implementation.

This module implements the v3 hidden service rendezvous protocol for
connecting to .onion addresses.

Protocol flow:
1. Build circuit to rendezvous point, establish rendezvous
2. Build circuit to introduction point, send INTRODUCE1
3. Wait for RENDEZVOUS2, complete hs-ntor handshake
4. Add HS hop to rendezvous circuit

See: https://spec.torproject.org/rend-spec/rendezvous-protocol.html
"""

from __future__ import annotations

import base64
import sys
import time
from dataclasses import dataclass

from torscope.cache import get_ed25519_from_cache
from torscope.crypto.proof_of_work import PowParams, PowSolution, compute_pow
from torscope.directory.hs_descriptor import IntroductionPoint
from torscope.directory.models import ConsensusDocument, RouterStatusEntry
from torscope.microdesc import get_ntor_key
from torscope.onion.address import OnionAddress
from torscope.onion.circuit import Circuit
from torscope.onion.connection import RelayConnection
from torscope.onion.hs_ntor import (
    HsNtorClientState,
    create_introduce1_encrypted_payload,
    generate_rendezvous_cookie,
)
from torscope.onion.ntor import HsCircuitKeys
from torscope.onion.relay import (
    IntroduceAckStatus,
    LinkSpecifier,
    RelayCell,
    RelayCommand,
    RelayCrypto,
    build_introduce1_cell_without_mac,
    create_establish_rendezvous_payload,
    parse_introduce_ack,
    parse_rendezvous2,
)
from torscope.path import PathSelector


@dataclass
class RendezvousResult:
    """Result of a successful rendezvous."""

    circuit: Circuit
    connection: RelayConnection


class RendezvousError(Exception):
    """Error during rendezvous protocol."""


def select_rendezvous_point(consensus: ConsensusDocument) -> RouterStatusEntry:
    """Select a suitable rendezvous point.

    Requirements:
    - Must have Fast and Stable flags
    - Should not be a directory authority

    Args:
        consensus: Network consensus

    Returns:
        Selected rendezvous point router
    """
    import random

    candidates = []
    for router in consensus.routers:
        if "Fast" in router.flags and "Stable" in router.flags:
            # Skip authorities
            if "Authority" not in router.flags:
                candidates.append(router)

    if not candidates:
        raise RendezvousError("No suitable rendezvous points found")

    # Bandwidth-weighted selection
    total_bw = sum(r.bandwidth or 0 for r in candidates)
    if total_bw == 0:
        return random.choice(candidates)

    r = random.randint(0, total_bw - 1)
    cumulative = 0
    for router in candidates:
        cumulative += router.bandwidth or 0
        if r < cumulative:
            return router

    return candidates[-1]  # Fallback


def get_router_ntor_key(router: RouterStatusEntry, _timeout: int = 30) -> bytes:
    """Get ntor key for a router, from cache or by fetching.

    Args:
        router: Router to get key for
        _timeout: Unused, kept for API compatibility

    Returns:
        32-byte ntor-onion-key

    Raises:
        RendezvousError: If key cannot be obtained
    """
    result = get_ntor_key(router)
    if result is None:
        raise RendezvousError(f"Failed to get ntor key for {router.nickname}")
    return result[0]


def build_circuit_to_router(
    consensus: ConsensusDocument,
    target: RouterStatusEntry,
    num_hops: int = 3,
    timeout: float = 30.0,
    verbose: bool = False,
) -> tuple[Circuit, RelayConnection]:
    """Build a circuit ending at the target router.

    Args:
        consensus: Network consensus
        target: Target router (will be the exit/last hop)
        num_hops: Number of hops (default 3)
        timeout: Connection timeout
        verbose: Print debug info

    Returns:
        Tuple of (circuit, connection)

    Raises:
        RendezvousError: If circuit building fails
    """

    def _log(msg: str) -> None:
        if verbose:
            print(f"  [rendezvous] {msg}", file=sys.stderr)

    # Select path with target as exit
    selector = PathSelector(consensus)
    try:
        path = selector.select_path(num_hops=num_hops, exit_router=target)
    except ValueError as e:
        raise RendezvousError(f"Failed to select path: {e}") from e

    routers = path.routers
    _log(f"Selected path: {' -> '.join(r.nickname for r in routers)}")

    # Get ntor keys for all routers
    ntor_keys = []
    for router in routers:
        try:
            ntor_key = get_router_ntor_key(router, int(timeout))
            ntor_keys.append(ntor_key)
        except RendezvousError as e:
            raise RendezvousError(f"Failed to get ntor key for {router.nickname}: {e}") from e

    # Connect to first router
    first_router = routers[0]
    _log(f"Connecting to {first_router.nickname} ({first_router.ip}:{first_router.orport})")

    conn = RelayConnection(host=first_router.ip, port=first_router.orport, timeout=timeout)

    try:
        conn.connect()
        if not conn.handshake():
            raise RendezvousError("TLS handshake failed")

        # Create circuit
        circuit = Circuit.create(conn)
        _log(f"Created circuit {circuit.circ_id}")

        # Extend to each hop
        for i, (router, ntor_key) in enumerate(zip(routers, ntor_keys, strict=True)):
            _log(f"Extending to hop {i+1}: {router.nickname}")
            if i == 0:
                if not circuit.extend_to(router.fingerprint, ntor_key):
                    raise RendezvousError(f"Failed to extend to {router.nickname}")
            else:
                if not circuit.extend_to(
                    router.fingerprint, ntor_key, ip=router.ip, port=router.orport
                ):
                    raise RendezvousError(f"Failed to extend to {router.nickname}")

        return circuit, conn

    except Exception as e:
        conn.close()
        raise RendezvousError(f"Circuit building failed: {e}") from e


def establish_rendezvous(
    circuit: Circuit,
    verbose: bool = False,
) -> bytes:
    """Establish rendezvous on a circuit.

    Sends ESTABLISH_RENDEZVOUS and waits for RENDEZVOUS_ESTABLISHED.

    Args:
        circuit: Circuit to the rendezvous point
        verbose: Print debug info

    Returns:
        20-byte rendezvous cookie

    Raises:
        RendezvousError: If establishment fails
    """

    def _log(msg: str) -> None:
        if verbose:
            print(f"  [rendezvous] {msg}", file=sys.stderr)

    # Generate random cookie
    cookie = generate_rendezvous_cookie()
    _log(f"Rendezvous cookie: {cookie.hex()}")

    # Send ESTABLISH_RENDEZVOUS
    establish_cell = RelayCell(
        relay_command=RelayCommand.ESTABLISH_RENDEZVOUS,
        stream_id=0,
        data=create_establish_rendezvous_payload(cookie),
    )
    circuit.send_relay(establish_cell)

    # Wait for RENDEZVOUS_ESTABLISHED
    response = circuit.recv_relay()
    if response is None:
        raise RendezvousError("No response to ESTABLISH_RENDEZVOUS")

    if response.relay_command == RelayCommand.RENDEZVOUS_ESTABLISHED:
        _log("Rendezvous established")
        return cookie

    raise RendezvousError(
        f"Unexpected response to ESTABLISH_RENDEZVOUS: {response.relay_command.name}"
    )


def send_introduce(
    circuit: Circuit,
    intro_point: IntroductionPoint,
    rendezvous_cookie: bytes,
    rendezvous_point: RouterStatusEntry,
    rendezvous_ntor_key: bytes,
    subcredential: bytes,
    verbose: bool = False,
    pow_params: PowParams | None = None,
    blinded_key: bytes | None = None,
) -> HsNtorClientState:
    """Send INTRODUCE1 cell to introduction point.

    Args:
        circuit: Circuit to the introduction point
        intro_point: Introduction point data from descriptor
        rendezvous_cookie: 20-byte rendezvous cookie
        rendezvous_point: Rendezvous point router
        rendezvous_ntor_key: Rendezvous point's ntor key
        subcredential: 32-byte subcredential
        verbose: Print debug info
        pow_params: Optional PoW parameters from descriptor (Proposal 327)
        blinded_key: 32-byte blinded public key (required if pow_params provided)

    Returns:
        HsNtorClientState for completing the handshake

    Raises:
        RendezvousError: If introduction fails
    """

    def _log(msg: str) -> None:
        if verbose:
            print(f"  [rendezvous] {msg}", file=sys.stderr)

    # Get auth_key and enc_key from intro point
    if intro_point.auth_key is None:
        raise RendezvousError("Introduction point missing auth_key")
    if intro_point.enc_key is None:
        raise RendezvousError("Introduction point missing enc_key")

    # Create hs-ntor client state
    hs_ntor = HsNtorClientState.create(
        enc_key=intro_point.enc_key,
        auth_key=intro_point.auth_key,
        subcredential=subcredential,
    )

    # Build rendezvous point link specifiers
    rp_specs = [
        LinkSpecifier.from_ipv4(rendezvous_point.ip, rendezvous_point.orport),
        LinkSpecifier.from_legacy_id(rendezvous_point.fingerprint),
    ]
    # Add Ed25519 identity if available (from consensus or cache)
    ed_key = None
    if rendezvous_point.ed25519_identity:
        ed_key = base64.b64decode(rendezvous_point.ed25519_identity + "=")
    elif rendezvous_point.microdesc_hash:
        ed_key = get_ed25519_from_cache(rendezvous_point.microdesc_hash)
    if ed_key:
        rp_specs.append(LinkSpecifier.from_ed25519_id(ed_key))

    # Log RP link specifiers
    _log(f"RP link specifiers: {len(rp_specs)} specs")
    for s in rp_specs:
        if s.spec_type == 0:  # IPv4
            ip_str = ".".join(str(b) for b in s.data[:4])
            port = (s.data[4] << 8) | s.data[5]
            _log(f"  IPv4: {ip_str}:{port}")
        elif s.spec_type == 2:  # Legacy ID
            _log(f"  Legacy ID: {s.data.hex()}")
        elif s.spec_type == 3:  # Ed25519 ID
            _log(f"  Ed25519 ID: {s.data.hex()[:32]}...")

    # Create encrypted payload plaintext
    encrypted_plaintext = create_introduce1_encrypted_payload(
        rendezvous_cookie=rendezvous_cookie,
        rendezvous_link_specifiers=[(s.spec_type, s.data) for s in rp_specs],
        rendezvous_onion_key=rendezvous_ntor_key,
    )

    # Encrypt with hs-ntor keys
    ciphertext = hs_ntor.encrypt_introduce_data(encrypted_plaintext)

    # Compute PoW if parameters are provided (Proposal 327)
    pow_solution: PowSolution | None = None
    if pow_params is not None:
        if blinded_key is None:
            raise RendezvousError("blinded_key required when pow_params provided")
        _log(f"Computing PoW (effort={pow_params.suggested_effort})...")
        pow_solution = compute_pow(
            seed=pow_params.seed,
            blinded_id=blinded_key,
            effort=pow_params.suggested_effort,
        )
        if pow_solution is None:
            _log("PoW computation failed, sending without PoW")
        else:
            _log("PoW computed successfully")

    # Build INTRODUCE1 cell without MAC
    cell_without_mac = build_introduce1_cell_without_mac(
        auth_key=intro_point.auth_key,
        client_pk=hs_ntor.client_pubkey,
        encrypted_data=ciphertext,
        pow_solution=pow_solution,
    )

    # Compute MAC over the entire cell (per Tor's compute_introduce_mac)
    mac = hs_ntor.compute_introduce_mac(cell_without_mac)

    # Complete the INTRODUCE1 cell by appending the MAC
    introduce1_data = cell_without_mac + mac

    _log(f"Sending INTRODUCE1 ({len(introduce1_data)} bytes)")
    _log(f"  intro auth_key: {intro_point.auth_key.hex()[:32]}...")
    _log(f"  intro enc_key: {intro_point.enc_key.hex()[:32]}...")
    _log(f"  client_pk: {hs_ntor.client_pubkey.hex()[:32]}...")
    _log(f"  subcredential: {subcredential.hex()[:32]}...")

    # Send INTRODUCE1
    introduce1_cell = RelayCell(
        relay_command=RelayCommand.INTRODUCE1,
        stream_id=0,
        data=introduce1_data,
    )
    circuit.send_relay(introduce1_cell)

    # Wait for INTRODUCE_ACK
    response = circuit.recv_relay()
    if response is None:
        raise RendezvousError("No response to INTRODUCE1")

    if response.relay_command == RelayCommand.INTRODUCE_ACK:
        status, success = parse_introduce_ack(response.data)
        if success:
            _log("INTRODUCE_ACK: success")
            return hs_ntor

        status_names = {
            IntroduceAckStatus.SUCCESS: "success",
            IntroduceAckStatus.SERVICE_NOT_RECOGNIZED: "service not recognized",
            IntroduceAckStatus.BAD_MESSAGE_FORMAT: "bad message format",
            IntroduceAckStatus.RELAY_FAILED: "relay to service failed",
        }
        raise RendezvousError(f"INTRODUCE_ACK failed: {status_names.get(status, str(status))}")

    raise RendezvousError(f"Unexpected response to INTRODUCE1: {response.relay_command.name}")


def complete_rendezvous(
    circuit: Circuit,
    hs_ntor: HsNtorClientState,
    timeout: float = 60.0,  # pylint: disable=unused-argument
    verbose: bool = False,
) -> None:
    """Wait for RENDEZVOUS2 and complete the handshake.

    Args:
        circuit: Circuit to the rendezvous point
        hs_ntor: hs-ntor client state from send_introduce
        timeout: Timeout for waiting (not currently enforced at this level)
        verbose: Print debug info

    Raises:
        RendezvousError: If handshake fails
    """

    def _log(msg: str) -> None:
        if verbose:
            print(f"  [rendezvous] {msg}", file=sys.stderr)

    _log("Waiting for RENDEZVOUS2...")

    # Wait for RENDEZVOUS2, handling PADDING cells
    start_time = time.time()
    response = None
    while time.time() - start_time < timeout:
        try:
            response = circuit.recv_relay(debug=verbose)
            if response is not None:
                break
            # recv_relay returned None - could be DESTROY or unknown cell
            # Check if circuit is still open
            if not circuit.is_open:
                raise RendezvousError("Circuit was destroyed while waiting for RENDEZVOUS2")
        except (TimeoutError, OSError):
            # Socket timeout - retry
            continue

    if response is None:
        raise RendezvousError("No RENDEZVOUS2 received (timeout or circuit destroyed)")

    if response.relay_command != RelayCommand.RENDEZVOUS2:
        raise RendezvousError(f"Expected RENDEZVOUS2, got {response.relay_command.name}")

    # Parse RENDEZVOUS2
    parsed = parse_rendezvous2(response.data)
    if parsed is None:
        raise RendezvousError("Failed to parse RENDEZVOUS2")

    server_pk, auth = parsed
    _log(f"Received RENDEZVOUS2: server_pk={server_pk.hex()[:16]}...")

    # Complete hs-ntor handshake
    key_material = hs_ntor.complete_rendezvous(server_pk, auth)
    if key_material is None:
        raise RendezvousError("hs-ntor handshake verification failed")

    _log("hs-ntor handshake completed")
    _log(f"  key_material: {key_material.hex()[:32]}... ({len(key_material)} bytes)")

    # Add hidden service hop to circuit
    # HS hops use SHA3-256 (32-byte digests) and AES-256 (32-byte keys)
    keys = HsCircuitKeys.from_key_material(key_material)
    _log(f"  Df: {keys.digest_forward.hex()[:32]}... (32 bytes)")
    _log(f"  Db: {keys.digest_backward.hex()[:32]}... (32 bytes)")
    _log(f"  Kf: {keys.key_forward.hex()[:32]}... (32 bytes)")
    _log(f"  Kb: {keys.key_backward.hex()[:32]}... (32 bytes)")
    # Use create_hs for hidden service hop (SHA3-256 digests, AES-256 encryption)
    crypto_layer = RelayCrypto.create_hs(
        key_forward=keys.key_forward,
        key_backward=keys.key_backward,
        digest_forward=keys.digest_forward,
        digest_backward=keys.digest_backward,
    )
    circuit._crypto_layers.append(crypto_layer)  # pylint: disable=protected-access

    _log("Hidden service hop added to circuit (SHA3-256 digests, AES-256 encryption)")


def rendezvous_connect(
    consensus: ConsensusDocument,
    onion_address: OnionAddress,
    introduction_points: list[IntroductionPoint],
    subcredential: bytes,
    timeout: float = 30.0,
    verbose: bool = False,
    pow_params: PowParams | None = None,
    blinded_key: bytes | None = None,
) -> RendezvousResult:
    """Perform complete rendezvous protocol to connect to a hidden service.

    Args:
        consensus: Network consensus
        onion_address: Parsed onion address
        introduction_points: Introduction points from descriptor
        subcredential: 32-byte subcredential
        timeout: Connection timeout
        verbose: Print debug info
        pow_params: Optional PoW parameters from descriptor (Proposal 327)
        blinded_key: 32-byte blinded public key (required if pow_params provided)

    Returns:
        RendezvousResult with circuit and connection

    Raises:
        RendezvousError: If rendezvous fails
    """

    def _log(msg: str) -> None:
        if verbose:
            print(f"[rendezvous] {msg}", file=sys.stderr)

    _log(f"Connecting to {onion_address.address[:16]}...")

    if not introduction_points:
        raise RendezvousError("No introduction points available")

    # Step 1: Select and build circuit to rendezvous point (with retries)
    _log("Step 1: Selecting rendezvous point...")
    rp_circuit = None
    rp_conn = None
    rp = None
    rp_ntor_key = None
    rp_last_error = None

    for rp_attempt in range(3):  # Try up to 3 different rendezvous points
        try:
            rp = select_rendezvous_point(consensus)
            _log(f"Selected rendezvous point: {rp.nickname} ({rp.ip}:{rp.orport})")

            rp_ntor_key = get_router_ntor_key(rp, int(timeout))

            _log("Building circuit to rendezvous point...")
            rp_circuit, rp_conn = build_circuit_to_router(
                consensus, rp, num_hops=3, timeout=timeout, verbose=verbose
            )
            break  # Success!
        except RendezvousError as e:
            rp_last_error = e
            _log(f"  Rendezvous point attempt {rp_attempt + 1} failed: {e}")
            continue

    if rp_circuit is None or rp_conn is None or rp is None or rp_ntor_key is None:
        raise RendezvousError(
            f"Failed to build rendezvous circuit after 3 attempts: {rp_last_error}"
        )

    try:
        # Step 2: Establish rendezvous
        _log("Step 2: Establishing rendezvous...")
        cookie = establish_rendezvous(rp_circuit, verbose=verbose)

        # Step 3: Try introduction points until one works
        _log("Step 3: Sending introduction...")
        last_error = None
        hs_ntor = None

        for i, intro_point in enumerate(introduction_points):
            ip_addr = intro_point.ip_address or "unknown"
            _log(f"Trying introduction point {i+1}/{len(introduction_points)}: {ip_addr}")

            try:
                # Find the intro point relay in consensus
                ip_router = None
                if intro_point.fingerprint:
                    for router in consensus.routers:
                        if router.fingerprint.upper() == intro_point.fingerprint.upper():
                            ip_router = router
                            break

                if ip_router is None:
                    _log(f"  Could not find intro point {intro_point.fingerprint} in consensus")
                    continue

                # Build circuit to introduction point
                ip_circuit, ip_conn = build_circuit_to_router(
                    consensus, ip_router, num_hops=3, timeout=timeout, verbose=verbose
                )

                try:
                    # Send INTRODUCE1
                    hs_ntor = send_introduce(
                        circuit=ip_circuit,
                        intro_point=intro_point,
                        rendezvous_cookie=cookie,
                        rendezvous_point=rp,
                        rendezvous_ntor_key=rp_ntor_key,
                        subcredential=subcredential,
                        verbose=verbose,
                        pow_params=pow_params,
                        blinded_key=blinded_key,
                    )
                    _log("INTRODUCE1 accepted")
                    break  # Success!

                finally:
                    ip_circuit.destroy()
                    ip_conn.close()

            except RendezvousError as e:
                last_error = e
                _log(f"  Introduction failed: {e}")
                continue

        if hs_ntor is None:
            raise RendezvousError(f"All introduction points failed: {last_error}")

        # Step 4: Complete rendezvous
        _log("Step 4: Completing rendezvous...")
        complete_rendezvous(rp_circuit, hs_ntor, timeout=timeout, verbose=verbose)

        _log("Rendezvous complete! Circuit ready for use.")
        return RendezvousResult(circuit=rp_circuit, connection=rp_conn)

    except Exception:
        rp_circuit.destroy()
        rp_conn.close()
        raise
