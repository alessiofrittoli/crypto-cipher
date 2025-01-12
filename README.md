# Node Module Starter 🛠️

[![NPM Latest Version][version-badge]][npm-url] [![Coverage Status][coverage-badge]][coverage-url] [![NPM Monthly Downloads][downloads-badge]][npm-url] [![Dependencies][deps-badge]][deps-url]

[version-badge]: https://img.shields.io/npm/v/%40alessiofrittoli%2Fnode-module-starter
[npm-url]: https://npmjs.org/package/%40alessiofrittoli%2Fnode-module-starter
[coverage-badge]: https://coveralls.io/repos/github/alessiofrittoli/node-module-starter/badge.svg
[coverage-url]: https://coveralls.io/github/alessiofrittoli/node-module-starter
[downloads-badge]: https://img.shields.io/npm/dm/%40alessiofrittoli%2Fnode-module-starter.svg
[deps-badge]: https://img.shields.io/librariesio/release/npm/%40alessiofrittoli%2Fnode-module-starter
[deps-url]: https://libraries.io/npm/%40alessiofrittoli%2Fnode-module-starter

## Starter repository for developing node_modules

### Table of Contents

- [Getting started](#getting-started)
- [Development](#development)
  - [ESLint](#eslint)
  - [Jest](#jest)
- [Contributing](#contributing)
- [Security](#security)
- [Credits](#made-with-)

---

### Getting started (delete once cloned in your project)

Run the following command to start using `node-module-starter` for your projects:

```bash
git clone git@github.com:alessiofrittoli/node-module-starter.git && git remote remove origin
```

install dependencies

```bash
pnpm i
```

Read the [Creating a repository from a template - GitHub Docs](https://docs.github.com/en/repositories/creating-and-managing-repositories/creating-a-repository-from-a-template) for more in-detail informations about creating a new Repository from a template using GitHub web interface.

---

### Getting started (customize based on your project needs)

Run the following command to start using `{package_name}` in your projects:

```bash
npm i {package_name}
```

or using `pnpm`

```bash
pnpm i {package_name}
```

---

### Development

#### Install depenendencies

```bash
npm install
```

or using `pnpm`

```bash
pnpm i
```

#### Build the source code

Run the following command to test and build code for distribution.

```bash
pnpm build
```

#### [ESLint](https://www.npmjs.com/package/eslint)

warnings / errors check.

```bash
pnpm lint
```

#### [Jest](https://npmjs.com/package/jest)

Run all the defined test suites by running the following:

```bash
# Run tests and watch file changes.
pnpm test:watch

# Run tests and watch file changes with jest-environment-jsdom.
pnpm test:jsdom

# Run tests in a CI environment.
pnpm test:ci

# Run tests in a CI environment with jest-environment-jsdom.
pnpm test:ci:jsdom
```

You can eventually run specific suits like so:

```bash
pnpm test:jest
pnpm test:jest:jsdom
```

Run tests with coverage.

An HTTP server is then started to serve coverage files from `./coverage` folder.

⚠️ You may see a blank page the first time you run this command. Simply refresh the browser to see the updates.

```bash
test:coverage:serve
```

---

### Contributing

Contributions are truly welcome!\
Please refer to the [Contributing Doc](./CONTRIBUTING.md) for more information on how to start contributing to this project.

---

### Security

If you believe you have found a security vulnerability, we encourage you to **_responsibly disclose this and NOT open a public issue_**. We will investigate all legitimate reports. Email `security@alessiofrittoli.it` to disclose any security vulnerabilities.

### Made with ☕

<table style='display:flex;gap:20px;'>
    <tbody>
        <tr>
            <td>
                <img alt="avatar" src='https://avatars.githubusercontent.com/u/35973186' style='width:60px;border-radius:50%;object-fit:contain;'>
            </td>
            <td>
                <table style='display:flex;gap:2px;flex-direction:column;'>
                    <tbody>
                        <tr>
                            <td>
                                <a href='https://github.com/alessiofrittoli' target='_blank' rel='noopener'>Alessio Frittoli</a>
                            </td>
                        </tr>
                        <tr>
                            <td>
                                <small>
                                    <a href='https://alessiofrittoli.it' target='_blank' rel='noopener'>https://alessiofrittoli.it</a> |
                                    <a href='mailto:info@alessiofrittoli.it' target='_blank' rel='noopener'>info@alessiofrittoli.it</a>
                                </small>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </td>
        </tr>
    </tbody>
</table>
