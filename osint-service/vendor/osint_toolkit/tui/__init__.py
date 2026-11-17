"""Textual user interface. A front-end over the same core used by the CLI:
:class:`~osint_toolkit.core.engine.Engine` runs investigations, consent goes through the
:class:`~osint_toolkit.core.privacy.ConsentProvider` protocol, progress through
:class:`~osint_toolkit.core.engine.ProgressListener`."""

from __future__ import annotations

from osint_toolkit.config import Settings


def run_tui(settings: Settings) -> int:
    from osint_toolkit.tui.app import OsintApp

    app = OsintApp(settings)
    app.run()
    return app.return_code or 0


__all__ = ["run_tui"]
