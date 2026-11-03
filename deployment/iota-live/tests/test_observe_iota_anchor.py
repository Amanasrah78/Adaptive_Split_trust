import importlib.util
import pathlib
import sys
import unittest


SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "observe_iota_anchor.py"
SPEC = importlib.util.spec_from_file_location("observe_iota_anchor", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ObserverTests(unittest.TestCase):
    def test_bytes32_accepts_exact_byte_vector(self):
        self.assertEqual(MODULE.bytes32(list(range(32)), "digest"), bytes(range(32)).hex())

    def test_bytes32_rejects_wrong_length(self):
        with self.assertRaises(MODULE.ObservationError):
            MODULE.bytes32([0] * 31, "digest")

    def test_transaction_digest_mapping_is_deterministic(self):
        first = MODULE.digest32_from_iota_text("4vQexample")
        second = MODULE.digest32_from_iota_text("4vQexample")
        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)

    def test_agreement_includes_all_security_relevant_fields(self):
        observation = {
            "network_id": "testnet",
            "package_id": "0x2",
            "object_id": "0x1",
            "object_version": 2,
            "previous_transaction": "tx",
            "package_version": 1,
            "epoch": 1,
            "predecessor_hash": "00" * 32,
            "checkpoint_hash": "11" * 32,
            "activation_time": 1,
            "bundle_uri": "https://example.invalid/bundle.json",
            "governance_key_set_id": "governance-v1",
        }
        changed = dict(observation)
        changed["checkpoint_hash"] = "22" * 32
        self.assertNotEqual(MODULE.agreement_key(observation), MODULE.agreement_key(changed))


if __name__ == "__main__":
    unittest.main()
