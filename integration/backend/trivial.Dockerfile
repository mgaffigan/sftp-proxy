FROM node:22-alpine

WORKDIR /app
COPY backend/package.json .
RUN npm install --omit=dev

CMD ["node", "server.js"]