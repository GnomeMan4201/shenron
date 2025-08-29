import importlib


def test_imports():
    assert importlib.import_module("shenron_modules.recon.osint_name_scraper")
    assert importlib.import_module("shenron_modules.recon.osint_name_adapter")
