"""AVB stock-boot JSON CLI bridge (S009 thin boundary over the frozen module).

Contract:

* ``main(argv=None) -> int`` where ``argv`` excludes interpreter/script and
  defaults to ``sys.argv[1:]``.
* Exactly one argument: a UTF-8 JSON request file.
* schemaVersion 1 request object with exactly the keys ``schemaVersion``,
  ``stockBootPath``, ``currentBootPath``, ``slotVbmetaPath``,
  ``trustedBaselinePath``, ``slot``, ``model``, ``partitionSizeBytes``.
* Exit codes: 0 success, 2 validation, 3 input, 4 io.
* Exactly one JSON document on stdout with a trailing newline for every
  handled outcome.

The frozen ``avb_stock`` module stays the sole crypto/trust/fingerprint
authority: this file only validates request shape, hands open read-only binary
streams to ``validate_restore_candidate`` and serialises its evidence. It never
supplies an expected fingerprint and never inspects image bytes itself.

Importing this module is side-effect free: no argument parsing, no file reads,
no device access.
"""

import json
import sys
from dataclasses import asdict

from avb_stock import StockBootValidationError, validate_restore_candidate

SCHEMA_VERSION = 1

EXIT_OK = 0
EXIT_VALIDATION = 2
EXIT_INPUT = 3
EXIT_IO = 4

_REQUEST_KEYS = frozenset(
    (
        "schemaVersion",
        "stockBootPath",
        "currentBootPath",
        "slotVbmetaPath",
        "trustedBaselinePath",
        "slot",
        "model",
        "partitionSizeBytes",
    )
)
_PATH_KEYS = (
    "stockBootPath",
    "currentBootPath",
    "slotVbmetaPath",
    "trustedBaselinePath",
)
_SLOTS = ("a", "b")


class _InputError(Exception):
    """Request argument, encoding, JSON or schema shape violation."""


def _emit(payload) -> None:
    """Write exactly one JSON document plus newline to stdout."""
    print(json.dumps(payload))


def _error_payload(kind, exc) -> dict:
    message = str(exc).strip() or "%s error" % kind
    return {
        "schemaVersion": SCHEMA_VERSION,
        "ok": False,
        "error": {"kind": kind, "message": message},
    }


def _validate_request(request) -> None:
    """Reject every shape/type/schema problem before any image is opened."""
    if not isinstance(request, dict):
        raise _InputError("request must be a JSON object")
    if set(request) != _REQUEST_KEYS:
        raise _InputError(
            "request must contain exactly the schemaVersion 1 key set"
        )

    schema_version = request["schemaVersion"]
    if type(schema_version) is not int or schema_version != SCHEMA_VERSION:
        raise _InputError("schemaVersion must be the integer 1")

    for key in _PATH_KEYS:
        value = request[key]
        if not isinstance(value, str) or not value:
            raise _InputError("%s must be a nonempty string" % key)

    slot = request["slot"]
    if not isinstance(slot, str) or slot not in _SLOTS:
        raise _InputError("slot must be 'a' or 'b'")

    model = request["model"]
    if not isinstance(model, str) or not model:
        raise _InputError("model must be a nonempty string")

    partition_size = request["partitionSizeBytes"]
    if type(partition_size) is not int or partition_size <= 0:
        raise _InputError("partitionSizeBytes must be a positive integer")


def _load_request(path):
    """Read and parse the request file, then validate it."""
    with open(path, "r", encoding="utf-8-sig") as handle:
        text = handle.read()
    request = json.loads(text)
    _validate_request(request)
    return request


def _run_validator(request):
    """Stream the four inputs read-only and delegate to the frozen module."""
    with open(request["stockBootPath"], "rb") as stock_boot, open(
        request["currentBootPath"], "rb"
    ) as current_boot, open(
        request["slotVbmetaPath"], "rb"
    ) as slot_vbmeta_handle, open(
        request["trustedBaselinePath"], "rb"
    ) as baseline_handle:
        slot_vbmeta = slot_vbmeta_handle.read()
        trusted_baseline = baseline_handle.read()
        return validate_restore_candidate(
            stock_boot=stock_boot,
            current_boot=current_boot,
            slot_vbmeta=slot_vbmeta,
            trusted_baseline=trusted_baseline,
            slot=request["slot"],
            model=request["model"],
            partition_size=request["partitionSizeBytes"],
        )


def _dispatch(argv):
    if len(argv) != 1:
        raise _InputError("expected exactly one request file argument")
    request_path = argv[0]
    if not isinstance(request_path, str) or not request_path:
        raise _InputError("request file argument must be a nonempty string")
    request = _load_request(request_path)
    return _run_validator(request)


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    try:
        evidence = _dispatch(argv)
    except StockBootValidationError as exc:
        _emit(_error_payload("validation", exc))
        return EXIT_VALIDATION
    except OSError as exc:
        _emit(_error_payload("io", exc))
        return EXIT_IO
    except _InputError as exc:
        _emit(_error_payload("input", exc))
        return EXIT_INPUT
    except ValueError as exc:
        _emit(_error_payload("input", exc))
        return EXIT_INPUT

    _emit(
        {
            "schemaVersion": SCHEMA_VERSION,
            "ok": True,
            "evidence": asdict(evidence),
        }
    )
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
