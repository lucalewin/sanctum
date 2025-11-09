# SanctumPass

SanctumPass is a Zero-Knowledge Password Manager written in Rust.

## Features

- Zero-Knowledge Authentication
  Our servers never see your password, not even for authentication.
- Secure Password Storage
  Your credentials are **encrypted on your device**. We never see them in plaintext.
  Our servers never receive any secrets in plaintext form.
- Cross-Platform Compatibility
  SanctumPass is available on Windows, macOS, and Linux.

## Development

```sh
# start the database and cache
docker compose up -d

# run the backend
cargo run --bin sanctum

# run the frontend TUI
cargo run --bin sanctum-tui
```

## Roadmap

- [ ] Add support for multiple vaults
- [ ] Implement password strength checker
- [ ] Add support for password generation
- [ ] Add support for password sharing
- [ ] Add full offline support
- [ ] Enterprise self-hosted
- [ ] SSH-Agent support
- [ ] Arbitrary record type support

## Contributing

Contributions are welcome! Please read our [contributing guidelines](CONTRIBUTING.md).

## License

The client applications (found in `sanctum-tui`, `sanctum-cli` and `sanctum-desktop`) are licensed under the MIT License.
