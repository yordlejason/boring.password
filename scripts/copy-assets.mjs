import { cp, mkdir } from 'node:fs/promises';
await mkdir('dist/apps/admin-web', { recursive: true });
await cp('apps/admin-web', 'dist/apps/admin-web', { recursive: true });
await cp('db', 'dist/db', { recursive: true });
