#!/bin/bash
cd "$(dirname "$0")"
sudo apt install python3-poetry
poetry install
clear
DATABASE_URL=$1 poetry run python3 -m app
while [ $? -eq 100 ]; do
    echo "Exited due to a connection error, restarting..."
    DATABASE_URL=$1 poetry run python3 -m app
done