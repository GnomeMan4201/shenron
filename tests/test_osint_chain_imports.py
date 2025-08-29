import importlib


def test_imports():
    assert importlib.import_module("shenron_modules.recon.osint_deep_scraper")
    assert importlib.import_module("shenron_modules.recon.osint_deep_adapter")
    assert importlib.import_module("shenron_modules.recon.osint_google_adapter")
