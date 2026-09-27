"""Compatibility entry point for the ATLAS desktop application."""

from .atlas_ui import (
    APP_NAME,
    APP_TAGLINE,
    AtlasApp,
    discover_repo,
    main,
    resource_path,
    run_self_test,
    save_repo,
    settings_path,
)

W3SecApp = AtlasApp
APP_VERSION = "development"
