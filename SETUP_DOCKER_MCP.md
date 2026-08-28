# MCP client integration

The server speaks MCP over stdio. Configure your MCP client to start the repository launcher and leave Docker policy to that launcher.

## Command

Use an absolute repository path because desktop clients may start in another working directory:

```text
/absolute/path/to/kali-mcp-server/scripts/kali-mcp
```

Example arguments:

```text
--image
kali-mcp-server:latest
--workspace
/absolute/path/to/workspace
--artifacts
/absolute/path/to/artifacts
--results
/absolute/path/to/results
--reports
/absolute/path/to/reports
```

For clients whose configuration accepts a command plus argument array, place the launcher in `command` and each line above in `args`. Do not copy a raw `docker run` command into the client: doing so easily drops the launcher's read-only filesystem, capability, mount, profile, and network controls.

Test the exact command first:

```bash
/absolute/path/to/kali-mcp-server/scripts/kali-mcp \
  --image kali-mcp-server:latest \
  --workspace /absolute/path/to/workspace \
  --artifacts /absolute/path/to/artifacts \
  --results /absolute/path/to/results \
  --reports /absolute/path/to/reports \
  --dry-run
```

Then remove `--dry-run` in the client configuration and restart the client. The client should discover 42 preserved calls plus five additions.

Client configuration locations and schemas change independently of this repository. Consult the current official documentation for your MCP client. This project does not require or document a speculative Docker MCP Gateway registry format.

## Profile selection

- Omit `--profile` for the host default.
- Use `--profile linux-hardened` on Linux when bridge networking is sufficient.
- Apple Silicon accepts only `mac-hardened`.

Physical Apple Silicon Docker Desktop qualification is pending. Do not treat the green QEMU Linux/arm64 CI job as macOS qualification.

See [Quick start](QUICK_START.md) and [Deployment guide](DEPLOYMENT_GUIDE.md).
