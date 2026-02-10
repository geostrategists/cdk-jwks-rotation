import { defineConfig } from "tsdown";

export default defineConfig([
  {
    entry: ["src/index.ts"],
    format: ["esm", "cjs"],
    dts: true,
    sourcemap: true,
    clean: true,
    target: "es2022",
    outDir: "dist",
    external: [/^@aws-sdk\/.*/],
    treeshake: true,
    minify: false,
    inlineOnly: false,
  },
  {
    entry: ["src/lambda/rotation-handler.ts"],
    format: ["esm"],
    dts: false,
    sourcemap: true,
    clean: false,
    target: "es2022",
    outDir: "dist/lambda",
    external: [/^@aws-sdk\/.*/],
    treeshake: true,
    minify: false,
    inlineOnly: false,
  },
]);
