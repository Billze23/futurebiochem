FROM node:18-slim

# Install the native build tools required by better-sqlite3
RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package files first so npm install is cached when only code changes
COPY package*.json ./

# Install dependencies (compiles better-sqlite3 from source)
RUN npm install

# Copy the rest of the application
COPY . .

# Create the data directory for SQLite
RUN mkdir -p /app/data

EXPOSE 3000

CMD ["node", "server.js"]
