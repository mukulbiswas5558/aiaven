import asyncpg
from tools import constant as const


async def Db() -> asyncpg.Connection:
    return await asyncpg.connect(const.DATABASE_URL)
