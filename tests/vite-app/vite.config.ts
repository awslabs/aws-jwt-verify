import { defineConfig } from "vite";
import resolve from "@rollup/plugin-node-resolve";

// https://vitejs.dev/config/
export default defineConfig({
  build: {
    rollupOptions: {
      plugins: [resolve({ browser: true })],
    },
  },
});
