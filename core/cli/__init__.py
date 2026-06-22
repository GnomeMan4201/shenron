"""core/cli/__init__.py — public surface: print_banner(), build_parser()"""

BANNER = "  SHENRON // polymorphic framework // LANimals collective // gnomeman4201"


def print_banner():
    print()
    print(BANNER)
    print()


def build_parser():
    import argparse
    from core.cli.commands import quickstart, run, sigma, assumption, report, history, artifact, schema, export, audit, doctor, health, campaign, compare_scenarios

    p = argparse.ArgumentParser(
        prog="shenron",
        description="SHENRON — synthetic telemetry and detection validation pipeline",
    )
    sub = p.add_subparsers(dest="subcommand", metavar="COMMAND")

    quickstart.register(sub)
    run.register(sub)
    sigma.register(sub)
    assumption.register(sub)
    report.register(sub)
    history.register(sub)
    artifact.register(sub)
    schema.register(sub)
    export.register(sub)
    audit.register(sub)
    doctor.register(sub)
    health.register(sub)
    campaign.register(sub)
    compare_scenarios.register(sub)

    return p
