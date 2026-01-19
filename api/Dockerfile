FROM node:20-alpine

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm install

COPY tsconfig.json .
COPY src ./src

EXPOSE 3001

# Using dev mode for debugging the runtime compilation if needed
CMD [ "npm", "run", "dev" ]
