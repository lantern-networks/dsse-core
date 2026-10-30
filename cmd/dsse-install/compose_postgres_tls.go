package main

// Determine the actual postgres UID/GID from the same pinned image that runs
// Patroni. Host key files remain 0600; only this root init service can read them.
const composePostgresTLSInit = `  dsse-postgres-tls-init:
    image: ${DSSE_POSTGRES_IMAGE:?declare the reviewed Spilo image in data_layer}
    user: "0:0"
    network_mode: none
    entrypoint: ["/bin/sh", "-ec"]
    command:
      - |
        uid=$$(id -u postgres)
        gid=$$(id -g postgres)
        mkdir -p /private
        chown $$uid:$$gid /private
        chmod 0700 /private
        for name in store-client.pem database-server.pem database-ca.pem; do
          install -m 0644 -o $$uid -g $$gid /source/$$name /private/$$name
        done
        for name in store-client-key.pem database-server-key.pem; do
          install -m 0600 -o $$uid -g $$gid /source/$$name /private/$$name
        done
    volumes:
      - "./store-client.pem:/source/store-client.pem:ro"
      - "./store-client-key.pem:/source/store-client-key.pem:ro"
      - "./database-server.pem:/source/database-server.pem:ro"
      - "./database-server-key.pem:/source/database-server-key.pem:ro"
      - "./database-ca.pem:/source/database-ca.pem:ro"
      - "postgres-tls:/private"

`
