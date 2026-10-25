# SecureVault

Aplicativo desktop local para armazenar credenciais em um cofre criptografado.
As senhas são criptografadas no banco local e o cofre é protegido por uma senha
mestra.

## Desenvolvimento

Requisitos: Node.js, npm, Rust e as dependências de sistema do Tauri 2 para sua
plataforma.

```sh
npm install
npm run tauri dev
```

## Verificações

```sh
npm test
npm run check
npm run build
cd src-tauri && cargo test
```

O banco do aplicativo é criado em `app_data_dir` como `securevault.db`.
Mantenha uma cópia segura da senha mestra: ela não pode ser recuperada.
