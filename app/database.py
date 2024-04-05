"""
MIT License

Copyright (c) 2023 Oviyan Gandhi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
from __future__ import annotations
import asyncio
import asyncpg
import traceback as tb
from asyncpg.exceptions import InvalidAuthorizationSpecificationError, PostgresConnectionError
from contextlib import asynccontextmanager
from datetime import date, datetime
from sys import stderr
from typing import TYPE_CHECKING, Literal, TypeAlias, overload
from uuid import UUID
from .errors import *

if TYPE_CHECKING:
    from .api import USACOAPI
    from .types import ModuleList, ProblemList

ConnCtxMgr: TypeAlias = asyncpg.pool.PoolConnectionProxy
OptConn: TypeAlias = ConnCtxMgr | None

class UserCache:
    usernames: dict[str, UUID | None]
    tokens: dict[UUID, str]

    def __init__(self, usernames: dict[str, UUID | None], tokens: dict[UUID, str]):
        self.usernames = usernames
        self.tokens = tokens

    @classmethod
    async def from_db(cls, db: Database):
        usernames: dict[str, UUID | None] = {row["username"]: None for row in await db.fetch("SELECT username FROM users;")}
        tokens = {row["token"]: row["username"] for row in await db.fetch("SELECT username, token FROM tokens;")}
        for token, username in tokens.items():
            usernames[username] = token
        return cls(usernames, tokens)

    def __contains__(self, username: str) -> bool:
        return username in self.usernames

    @overload
    def __getitem__(self, key: str) -> UUID | None: ...

    @overload
    def __getitem__(self, key: UUID) -> str: ...

    def __getitem__(self, key):
        if isinstance(key, UUID):
            return self.tokens.get(key, None)
        return self.usernames.get(key, None)

    def __setitem__(self, key: str, value: UUID | None):
        self.usernames[key] = value
        if value:
            self.tokens[value] = key

    def __delitem__(self, key: str | UUID):
        if isinstance(key, UUID):
            self.usernames[self.tokens[key]] = None
            del self.tokens[key]
        else:
            tok = self.usernames[key]
            if tok:
                del self.tokens[tok]
            del self.usernames[key]

def check_username(coro):
    async def wrapper(self: Database, username: str, *args, **kwargs):
        if not self.user_exists(username):
            raise UnknownUsernameError(username)
        return await coro(self, username, *args, **kwargs)
    return wrapper


class Database:
    pool: asyncpg.Pool
    cache: UserCache

    def __init__(self, app: USACOAPI):
        app.router.lifespan_context = self.lifespan

    def acquire(self) -> asyncpg.pool.PoolAcquireContext:
        """Shorthand for .pool.acquire()"""
        return self.pool.acquire()

    async def release(self, conn: ConnCtxMgr):
        """Shorthand for .pool.release()"""
        await self.pool.release(conn)

    async def perform(self, attr: str, *args, conn: OptConn = None, **kwargs):
        acquired = False
        if not conn:
            acquired = True
            conn = await self.acquire()
        coro = getattr(conn, attr)
        try:
            ret = await coro(*args, **kwargs)
        except (InvalidAuthorizationSpecificationError, PostgresConnectionError) as err:
            await self.release(conn)
            asyncio.get_running_loop().close()
            tb.print_exception(type(err), err, err.__traceback__, file=stderr)
            exit(100)
        if acquired:
            await self.release(conn)
        return ret

    async def execute(self, query: str, *args, conn: OptConn = None):
        """Executes a query on the database"""
        await self.perform("execute", query, *args, conn=conn)

    async def executemany(
            self, query: str, args: list[tuple], *, conn: OptConn = None
        ):
        """Executes a query on the database multiple times"""
        await self.perform("executemany", query, args, conn=conn)

    async def fetch(self, query: str, *args, conn: OptConn = None) -> list[asyncpg.Record]:
        """Fetches data from the database"""
        return await self.perform("fetch", query, *args, conn=conn)

    async def fetchrow(self, query: str, *args, conn: OptConn = None) -> asyncpg.Record:
        """Fetches a single row from the database"""
        return await self.perform("fetchrow", query, *args, conn=conn)

    async def invalidate_tokens(self):
        """Invalidates expired tokens once every day"""
        wait = False
        while True:
            if wait:
                await asyncio.sleep(24 * 60 * 60)
            else: wait = True
            deleted = await self.fetch("""
                DELETE FROM tokens
                    WHERE created < NOW() - INTERVAL '1 month'
                    RETURNING token;
            """)
            for row in deleted:
                del self.cache[row["token"]]

    @asynccontextmanager
    async def lifespan(self, app: USACOAPI):
        """Handles the opening and closing of the database connection pool"""
        # Initialize the database
        self.pool = await asyncpg.create_pool(**app.settings["database"]) # type: ignore
        with open("setup.sql", "r") as f:
            setup = f.read()
        await self.execute(setup)
        self.cache = await UserCache.from_db(self)
        task = asyncio.create_task(self.invalidate_tokens())
        yield
        # Close the pool
        task.cancel()
        await self.pool.close()

    def user_exists(self, name: str) -> bool:
        """Checks if a user exists"""
        return name in self.cache

    def get_username(self, token: UUID) -> str | None:
        """Gets the username associated with a token"""
        return self.cache[token]

    def autocomplete(self, name: str) -> list[str]:
        """Matches partial username with existing usernames"""
        name = name.lower()
        return [user for user in self.cache.usernames if user.lower().startswith(name)]

    async def signup(self, username: str, password: str, *, conn: OptConn = None) -> str:
        """Register a user into the database and return the token generated"""
        if self.user_exists(username):
            raise DuplicateError
        acquired = False
        if not conn:
            acquired = True
            conn = await self.acquire()
        try:
            await self.execute(
                """INSERT INTO users (username, password) VALUES (
                    $1, crypt($2, gen_salt('bf'))
                );""", username, password, conn=conn)
            token: asyncpg.Record = await self.fetchrow(
                """INSERT INTO tokens (username) VALUES ($1) RETURNING token;""",
                username, conn=conn
            )
        except Exception as exc:
            await self.release(conn)
            raise exc from None
        if acquired: await self.release(conn)
        self.cache[username] = token["token"]
        return str(token["token"])

    @check_username
    async def update_user(
            self, username: str, new_username: str | None = None,
            new_password: str | None = None, *, conn: OptConn = None
    ) -> str:
        """Updates a user's username or password and generate a new token"""
        if new_username and self.user_exists(new_username):
            raise DuplicateError
        acquired = False
        if not conn:
            acquired = True
            conn = await self.acquire()
        try:
            if new_username:
                await self.execute(
                    "UPDATE users SET username = $1 WHERE username = $2;",
                    new_username, username, conn=conn
                )
            if new_password:
                await self.execute(
                    "UPDATE users SET password = crypt($1, gen_salt('bf')) WHERE username = $2;",
                    new_password, username, conn=conn
                )
            token: asyncpg.Record = await self.fetchrow(
                """UPDATE tokens
                    SET token = uuid_generate_v4 ()
                    WHERE username = $1
                    RETURNING token;""",
                new_username or username, conn=conn
            )
        except Exception as exc:
            await self.release(conn)
            raise exc from None
        if acquired: await self.release(conn)
        del self.cache[username]
        self.cache[new_username or username] = token["token"]
        return str(token["token"])

    @check_username
    async def remove_user(self, username: str, *, conn: OptConn = None) -> None:
        """Removes a user from the database"""
        if self.user_exists(username):
            await self.execute(
                "DELETE FROM users WHERE username = $1;", username, conn=conn
            )
            del self.cache[username]

    @check_username
    async def get_token(self, username: str, password: str, *, conn: OptConn = None) -> dict:
        acquired = False
        if not conn:
            acquired = True
            conn = await self.acquire()
        try:
            rec = await self.fetchrow(
                """
                SELECT exists (
                    SELECT 1 FROM users
                        WHERE username = $1 AND password = crypt(TEXT($2), password) LIMIT 1
                );
                """, username, password, conn=conn
            )
            if not rec["exists"]:
                raise UnauthorizedError
            await self.execute(
                "INSERT INTO tokens(username) VALUES ($1) ON CONFLICT DO NOTHING;", username, conn=conn
            )
            rec = await self.fetchrow(
                "SELECT token, created FROM tokens WHERE username = $1;", username, conn=conn
            )
        except Exception as exc:
            await self.release(conn)
            raise exc from None
        if acquired: await self.release(conn)
        if not self.cache[username]:
            self.cache[username] = rec["token"]
        return {
            "token": str(rec["token"]),
            "expiry": str(date(
                year = rec["created"].year + int(rec["created"].month/12),
                month = (rec["created"].month % 12) + 1, day = rec["created"].day
            ))
        }

    async def remove_token(self, username: str, *, conn: OptConn = None) -> None:
        if self.cache[username]:
            await self.execute(
                "DELETE FROM tokens WHERE username = $1;", username, conn=conn
            )
            self.cache[username] = None

    @check_username
    async def get_progress(
            self, username: str, tname: Literal["modules", "problems"], *, conn: OptConn = None
    ) -> dict:
        if tname not in ("modules", "problems"):
            if conn:
                await self.release(conn)
            raise ValueError("tname must be either 'modules' or 'problems'")
        data = {
            row["id"]: dict(row)
            for row in (await self.fetch(
                f"""SELECT id, progress, lastUpdated FROM {tname} WHERE username = $1;""",
                username, conn=conn
            ))
        }
        for value in data.values():
            value["lastUpdated"] = value["lastupdated"].timestamp()
            del value["lastupdated"]
        return data

    @check_username
    async def get_follows(self, username: str, *, conn: OptConn = None) -> list[str]:
        return [row["follow"] for row in (await self.fetch("""
            SELECT follow FROM follows WHERE username = $1 ORDER BY follow ASC;
        """, username, conn=conn))]

    @check_username
    async def update_progress(
            self, username: str, tname: Literal["modules", "problems"],
            proglist: ModuleList | ProblemList, *, conn: OptConn = None
    ):
        if tname not in ("modules", "problems"):
            raise ValueError("tname must be either 'modules' or 'problems'")
        if len(getattr(proglist, tname)) == 0: return
        await self.executemany(f"""
            INSERT INTO {tname} (id, username, progress, lastUpdated)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (id, username)
                    DO UPDATE SET progress = $3, lastUpdated = $4;
        """, [
            (progress.id, username,
            progress.progress, datetime.fromtimestamp(progress.lastUpdated))
            for progress in getattr(proglist, tname)
        ], conn=conn)

    @check_username
    async def follow(
        self, username: str, to_follow: str, *, conn: OptConn = None
    ):
        if not self.user_exists(to_follow):
            raise UnknownUsernameError(to_follow)
        acquired = False
        if not conn:
            acquired = True
            conn = await self.acquire()
        try:
            await self.execute("""
                INSERT INTO follows (username, follow) VALUES ($1, $2);
            """, username, to_follow, conn=conn)
        except asyncpg.UniqueViolationError:
            await self.release(conn)
            raise DuplicateError
        except Exception as exc:
            await self.release(conn)
            raise exc from None
        ret: dict[str, dict] = {}
        for tname in ("problems", "modules"):
            ret[tname] = await self.get_progress(to_follow, tname, conn=conn)
        if acquired:
            await self.release(conn)
        return ret

    async def unfollow(
        self, username: str, to_unfollow: str, *, conn: OptConn = None
    ):
        if self.user_exists(username) and self.user_exists(to_unfollow):
            await self.execute("""
                DELETE FROM follows WHERE username = $1 AND follow = $2;
            """, username, to_unfollow, conn=conn)

    @check_username
    async def get_follower_progress(self, username: str, *, conn: OptConn = None) -> dict:
        acquired = False
        if not conn:
            acquired = True
            conn = await self.acquire()
        try:
            problems = await self.fetch("""
                SELECT * FROM problems WHERE username IN (
                    SELECT follow FROM follows WHERE username = $1
                );
            """, username, conn=conn)
            modules = await self.fetch("""
                SELECT * FROM modules WHERE username IN (
                    SELECT follow FROM follows WHERE username = $1
                );
            """, username, conn=conn)
        except asyncpg.ForeignKeyViolationError:
            raise UnknownUsernameError(username)
        except Exception as exc:
            await self.release(conn)
            raise exc from None
        if acquired: await self.release(conn)
        sorted_problems: dict[str, dict[str, dict]] = {}
        for problem in problems:
            sorted_problems.setdefault(problem["id"], {})
            fin = dict(problem)
            fin["lastUpdated"] = int(fin["lastupdated"].timestamp())
            k = fin["username"]
            del fin["lastupdated"]
            del fin["username"]
            sorted_problems[problem["id"]][k] = fin
        sorted_modules: dict[str, dict[str, dict]] = {}
        for module in modules:
            sorted_modules.setdefault(module["id"], {})
            fin = dict(module)
            fin["lastUpdated"] = int(fin["lastupdated"].timestamp())
            k = fin["username"]
            del fin["lastupdated"]
            del fin["username"]
            sorted_modules[module["id"]][k] = fin
        return {
            "problems": sorted_problems,
            "modules": sorted_modules
        }