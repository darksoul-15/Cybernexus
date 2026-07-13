/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Deployed backend origin (empty in dev — Vite proxies /api). */
  readonly VITE_API_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
