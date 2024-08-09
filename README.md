# Lugia WebDAV

This is just a bare bones WebDAV 1 file server, which supports the basic file operations (except locking).

## Usage

Generate salted login data used for the server:

```sh
cargo run --bin login
```

Start the server:

```sh
# if you want logging
export RUST_LOG=warn

cargo run -- 0.0.0.0:5000 -d <directory> -k cert/key.pem -c cert/cert.pen -l <login>
```

> Remember to replace `cert/key.pem` and `cert/cert.pem` with your own TSL certificates (execute `./cert/gen.sh`).

The `<directory>` is the path directory to be served and `<login>` is the previously generated login data.

## Reference

- https://datatracker.ietf.org/doc/html/rfc4918
