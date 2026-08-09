FROM node:22-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    g++ \
    make \
    pkg-config \
    libssl-dev \
    unzip \
    python3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth=1 https://github.com/zhlynn/zsign.git /tmp/zsign \
    && cd /tmp/zsign/build/linux \
    && make clean \
    && make \
    && install -m 0755 zsign /usr/local/bin/zsign \
    && rm -rf /tmp/zsign

WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .

ENV PORT=10000
EXPOSE 10000

CMD ["npm", "start"]
