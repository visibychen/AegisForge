from alembic import context
from app.core.config import Settings
from app.core.database import build_engine
from app.models import Base

target_metadata = Base.metadata


def run_migrations():
    settings = Settings()
    if context.is_offline_mode():
        context.configure(
            url=settings.resolved_database_url,
            target_metadata=target_metadata,
            literal_binds=True,
        )
        with context.begin_transaction():
            context.run_migrations()
    else:
        engine = build_engine(settings)
        try:
            with engine.connect() as connection:
                context.configure(
                    connection=connection, target_metadata=target_metadata, render_as_batch=True
                )
                with context.begin_transaction():
                    context.run_migrations()
        finally:
            engine.dispose()


run_migrations()
