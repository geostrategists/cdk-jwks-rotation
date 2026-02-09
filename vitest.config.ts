import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    reporters: "default",
    coverage: {
      reporter: ["text", "html"],
    },
    include: ["tests/**/*.test.ts", "tests/**/*.spec.ts"],
    setupFiles: ["./tests/setup.ts"],
  },
});
