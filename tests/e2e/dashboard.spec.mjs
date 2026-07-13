import { expect, test } from "@playwright/test";

test("dashboard loads governance controls without persisting API tokens", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "策略治理工作台" })).toBeVisible();
  await page.locator("#api-token").fill("ephemeral-token");
  await page.getByRole("button", { name: "应用 Token" }).click();
  await expect(page.locator("#api-token")).toHaveValue("");
  expect(await page.evaluate(() => localStorage.getItem("trustaix_token"))).toBeNull();
});
