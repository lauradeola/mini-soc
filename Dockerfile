FROM node:22-slim
WORKDIR /app

COPY backend/package*.json backend/
RUN cd backend && npm install --omit=dev

COPY backend backend
COPY frontend frontend

ENV NODE_ENV=production PORT=3000 DB_PATH=/data/soc.db
RUN mkdir /data && chown node:node /data
VOLUME /data
EXPOSE 3000

WORKDIR /app/backend
USER node
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s CMD node -e "fetch('http://localhost:'+(process.env.PORT||3000)+'/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "src/server.js"]
