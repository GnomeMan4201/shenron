import importlib


def test_import_adapter():
    mod = importlib.import_module("shenron_modules.recon.google_recon_adapter")
    assert hasattr(mod, "run_adapter")
