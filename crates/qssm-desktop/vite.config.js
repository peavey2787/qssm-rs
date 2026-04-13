import { defineConfig } from "vite";

// https://v2.tauri.app/start/create-project/
export default defineConfig({
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
  build: {
    outDir: "dist",
    emptyDir: true,
  },
});
