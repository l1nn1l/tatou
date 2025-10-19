# Auto-load plugins on startup (so they register themselves)
try:
    from . import plugins  # noqa: F401
except Exception as e:
    import logging
    logging.getLogger(__name__).warning("Failed to import plugins: %s", e)
