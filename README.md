# AllStarLink IAX Server

Multi-threaded IAX2 Registration Server written in NodeJS. Performs IAX2 registrations for Asterisk clients.

## Requirements
* NodeJS 12.x or greater
* Yarn 1.x

## Installation
* Copy .env.example to .env
* Change .env to fit your environment.
* Run `yarn install`
* Run `node ./iaxServer.js`

## Running with Docker
* Run `docker-compose up -d` to run as a daemon. Container uses host networking.

## Authors
* Rob Vella, KK9ROB <me@robvella.com>
* Jason VE3YCA

## License
A-GPL 3.0 or later

https://www.gnu.org/licenses/agpl-3.0.en.html

## Copyright
Copyright (C) 2020-2021 AllStarLink, Inc