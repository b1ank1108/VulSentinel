import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cve_poc_llm_reports.atomic_write import atomic_write_json


class TestAtomicWriteJson(unittest.TestCase):
    def test_atomic_write_overwrites_target(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = root / "out.json"
            path.write_text("{\"old\":true}\n", encoding="utf-8")

            atomic_write_json(path, {"new": True})

            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data, {"new": True})

    def test_atomic_write_does_not_create_file_on_serialize_error(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = root / "out.json"

            class _Unserializable:
                pass

            with self.assertRaises(TypeError):
                atomic_write_json(path, {"x": _Unserializable()})
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()

