import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "tests/e2e",
  use: { baseURL: process.env.TRUSTAIX_E2E_URL || "http://127.0.0.1:18000" },
  webServer: {
    command: "python -m uvicorn trustaix.main:app --host 127.0.0.1 --port 18000",
    url: "http://127.0.0.1:18000/health",
    reuseExistingServer: !process.env.CI,
  },
});
