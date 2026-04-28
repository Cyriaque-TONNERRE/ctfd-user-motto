# CTFd-UserMotto

A simple plugin that lets users display a custom motto on their profile.
Supports Jinja2 templating so users can include dynamic data like their
name, score, or affiliation.

## Features

- Per-user customizable motto (up to 280 characters)
- Jinja2 templating with a sandboxed environment
- Hardened sandbox blocking known RCE primitives
- Input validation against common injection patterns

## Installation

```bash
cd /opt/CTFd/CTFd/plugins
git clone https://github.com/ctf-org/ctfd-user-motto.git user_motto
# Restart CTFd
```

## Usage

Once installed, users can navigate to `/profile/motto` to set their motto.

### Example mottos

```
Hello, I'm {{ user.name }}!
Score: {{ user.score }} points and counting.
```

## Security notes

We take security seriously. The plugin uses `jinja2.sandbox.SandboxedEnvironment`
with a custom `MottoSandbox` subclass that blocks attribute access to known
RCE primitives (`popen`, `system`, `eval`, `subprocess`, etc.).

The motto input is also validated against a literal blacklist before
templating to provide defense in depth.

If you find a security issue, please open an issue on GitHub.

## License

MIT

## If you read up to here

There is no hint that you can find in other repo.