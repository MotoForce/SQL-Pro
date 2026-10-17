"""Initial schema bootstrap for new installations. For upgrades use reviewed migrations."""
from app.main import Base, engine
if __name__ == '__main__':
    Base.metadata.create_all(engine)
    print('Schema initialized')
