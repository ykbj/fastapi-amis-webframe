import asyncio

import databases
import sqlalchemy
from pydantic import BaseModel

from server.app.utils import get_password_hash

DATABASE_URL = "sqlite:///db/server.db"

database = databases.Database(DATABASE_URL)

engine = sqlalchemy.create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)

metadata = sqlalchemy.MetaData()

users = sqlalchemy.Table(
    "users",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("email", sqlalchemy.String),
    sqlalchemy.Column("hashed_password", sqlalchemy.String),
    sqlalchemy.Column("is_active", sqlalchemy.Boolean)
)

metadata.create_all(engine)


async def init_db():
    await database.connect()
    query = users.select()
    user = await database.fetch_all(query)
    if len(user) == 0:
        query_insert = users.insert()
        values = {
            "email": "yk1001@163.com",
            "hashed_password": get_password_hash('ykbjfree'),
            "is_active": True
        }
        await database.execute(query=query_insert, values=values)
    await database.disconnect()


loop = asyncio.get_event_loop()
result = loop.run_until_complete(init_db())
loop.close()


class User(BaseModel):
    id: int
    email: str
    hashed_password: str
    is_active: bool
