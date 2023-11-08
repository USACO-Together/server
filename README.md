# USACO Together : Server
The webserver which provides an API for the extension to interact with the database

The API is built with FastAPI and uses a PostgreSQL database.

To run your own version of the API in linux, use the following command:
```
./run.sh
```
You may optionally provide a database url to the above command.

You can also modify `settings.json` to customize options for [`asyncpg.create_pool`](https://magicstack.github.io/asyncpg/current/api/index.html#connection-pools) and [`uvicorn.run`](https://www.uvicorn.org/settings/).
