FROM node:18-alpine
WORKDIR /app
COPY . .
COPY .aws /root/.aws
RUN npm install
RUN yarn install --production
CMD ["node", "app.js"]
EXPOSE 3000