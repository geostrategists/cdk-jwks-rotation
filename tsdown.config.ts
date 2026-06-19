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
    deps: {
      neverBundle: [/^@aws-sdk\/.*/],
      onlyBundle: false,
    },
    treeshake: true,
    minify: false,
  },
  {
    entry: ["src/lambda/rotation-handler.ts"],
    format: ["esm"],
    dts: false,
    sourcemap: true,
    clean: false,
    target: "es2022",
    outDir: "dist/lambda",
    deps: {
      neverBundle: [/^@aws-sdk\/.*/],
      onlyBundle: false,
    },
    treeshake: true,
    minify: false,
  },
]);
