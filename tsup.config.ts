import { defineConfig } from "tsup";

import pkg from "./package.json";

export default defineConfig([
  {
    clean: true,
    entry: ["src/index.ts", "src/lambda/rotation-handler.ts"],
    format: ["cjs"],
    outDir: "dist",
    dts: true,
    external: [/^@aws-sdk\/.*/],
    banner: {
      js: `/**
* ${pkg.name} v${pkg.version}
*
* Copyright (c) Geostrategists Consulting GmbH. All rights reserved.
*
*/`,
    },
  },
]);
