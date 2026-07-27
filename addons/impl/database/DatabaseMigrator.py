"""Versioned database migration runner for the Database addon."""

from datetime import datetime, timezone

from addons.impl.database.Models import SchemaMigration


class DatabaseMigrator:
    def __init__(self, database, migrations):
        self._database = database
        self._migrations = tuple(sorted(migrations, key=lambda migration: migration.version))

    def migrate(self):
        self._database.connect(reuse_if_open=True)
        try:
            SchemaMigration.create_table(safe=True)
            appliedVersions = {
                migration.version
                for migration in SchemaMigration.select(SchemaMigration.version)
            }

            for migration in self._migrations:
                if migration.version in appliedVersions:
                    continue

                with self._database.atomic():
                    migration.apply(self._database)
                    SchemaMigration.create(version=migration.version, appliedAt=datetime.now(timezone.utc))
        finally:
            self._database.close()
