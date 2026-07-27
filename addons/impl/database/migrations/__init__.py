"""Ordered schema migrations for the Database addon."""

from addons.impl.database.migrations.V001InitialSchema import V001InitialSchema


MIGRATIONS = (V001InitialSchema(),)
