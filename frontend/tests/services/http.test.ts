import { describe, expect, it, vi } from "vitest";

import { api } from "../../src/services/api";
import { ApiError, request } from "../../src/services/http";
import { json, offline, recorded } from "../helpers";

describe("request", () => {
  it("returns the parsed body on success", async () => {
    const body = recorded("critical", "status").body;
    vi.stubGlobal("fetch", vi.fn(async () => json(body)));
    await expect(api.status()).resolves.toEqual(body);
  });

  it.each([
    [403, "forbidden"],
    [404, "not_found"],
    [409, "conflict"],
    [422, "invalid"],
    [429, "rate_limited"],
    [503, "unavailable"],
    [500, "server"],
  ] as const)("maps HTTP %i to %s", async (status, kind) => {
    vi.stubGlobal("fetch", vi.fn(async () => json({ detail: "nope" }, status)));
    const error = await request("/x").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).kind).toBe(kind);
    expect((error as ApiError).status).toBe(status);
  });

  it("reports a network failure as offline", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => offline()));
    const error = await request("/health").catch((e: unknown) => e);
    expect((error as ApiError).kind).toBe("offline");
  });

  it("never sends credentials", async () => {
    const fetchMock = vi.fn<[RequestInfo | URL, RequestInit?], Promise<Response>>(async () => json({}));
    vi.stubGlobal("fetch", fetchMock);
    await request("/health");
    const init = fetchMock.mock.calls[0]?.[1];
    expect(init?.credentials).toBe("omit");
  });

  it("only places public incident ids in URLs", () => {
    expect(() => api.incident("../../etc")).toThrow("invalid incident id");
    expect(() => api.explanation("SIT-1; DROP")).toThrow("invalid incident id");
  });
});
