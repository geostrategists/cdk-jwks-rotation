import { defineConfig } from "vitest/config";
import { resolve } from "node:path";

export default defineConfig({
  build: {
    lib: {
      entry: {
        index: resolve(__dirname, "src/index.ts"),
        "rotation-handler": resolve(__dirname, "src/lambda/rotation-handler.ts"),
      },
      formats: ["es"],
    },
    rollupOptions: {
      external: [
        "@aws-sdk/client-s3",
        "@aws-sdk/client-secrets-manager",
        "aws-cdk-lib",
        "constructs",
      ],
    },
  },
  test: {
    globals: true,
    environment: "node",
    setupFiles: ["./tests/setup.ts"],
  },
});
