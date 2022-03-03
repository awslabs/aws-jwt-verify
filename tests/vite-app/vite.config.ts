import { defineConfig } from "vite";
import alias from "@rollup/plugin-alias";

// https://vitejs.dev/config/
export default defineConfig({
  build: {
    rollupOptions: {
      plugins: [
        alias({
          entries: [
            {
              find: "#node-web-compat",
              replacement: "./node-web-compat-web.js",
            },
          ],
        }),
      ],
    },
  },
});
