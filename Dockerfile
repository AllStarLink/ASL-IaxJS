FROM node:12-buster

WORKDIR /app

RUN npm i -g cross-env
RUN yarn --no-bin-links

CMD npm start 
