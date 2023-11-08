/*
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
*/
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE TABLE IF NOT EXISTS users (
    username VARCHAR(32) PRIMARY KEY,
    password TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
    username VARCHAR(32) PRIMARY KEY
        REFERENCES users(username)
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    token UUID NOT NULL DEFAULT uuid_generate_v4 (),
    created DATE NOT NULL DEFAULT CURRENT_DATE
);
-- basically CREATE TYPE IF NOT EXISTS moduleProgress AS ENUM (...)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'moduleprogress') THEN
        CREATE TYPE moduleProgress AS ENUM ('Not Started', 'Reading', 'Practicing', 'Complete', 'Skipped', 'Ignored');
    END IF;
END
$$;
CREATE TABLE IF NOT EXISTS modules (
    id TEXT NOT NULL,
    username VARCHAR(32)
        REFERENCES users(username)
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    lastUpdated TIMESTAMP NOT NULL DEFAULT NOW(),
    progress moduleProgress,
    UNIQUE (id, username)
);
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'problemprogress') THEN
        CREATE TYPE problemProgress AS ENUM ('Not Attempted', 'Solving', 'Solved', 'Reviewing', 'Skipped', 'Ignored');
    END IF;
END
$$;
CREATE TABLE IF NOT EXISTS problems (
    id TEXT NOT NULL,
    username VARCHAR(32)
        REFERENCES users(username)
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    lastUpdated TIMESTAMP NOT NULL DEFAULT NOW(),
    progress problemProgress,
    UNIQUE (id, username)
);
CREATE TABLE IF NOT EXISTS follows (
    username VARCHAR(32)
        REFERENCES users(username)
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    follow VARCHAR(32)
        REFERENCES users(username)
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    CHECK (username <> follow),
    UNIQUE (username, follow)
);