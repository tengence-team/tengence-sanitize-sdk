import { describe, it, expect } from "vitest";
import { tokenizePath, mapPath, getPathValues, collectUnmatchedFields } from "../src/field";

describe("field 路径", () => {
  it("tokenize：a.b / items[*].price / a[*].b[*].c", () => {
    expect(tokenizePath("phone")).toEqual(["phone"]);
    expect(tokenizePath("contact.phone")).toEqual(["contact", "phone"]);
    expect(tokenizePath("items[*].price")).toEqual(["items", "*", "price"]);
    expect(tokenizePath("a[*].b[*].c")).toEqual(["a", "*", "b", "*", "c"]);
  });

  it("mapPath：嵌套对象原位修改", () => {
    const row = { contact: { phone: "13800138000" } };
    mapPath(row, tokenizePath("contact.phone"), () => "HASHED");
    expect(row.contact.phone).toBe("HASHED");
  });

  it("mapPath：数组逐元素变换", () => {
    const row = { items: [{ price: "1" }, { price: "2" }] };
    mapPath(row, tokenizePath("items[*].price"), (v) => `#${v}`);
    expect(row.items.map((i: { price: string }) => i.price)).toEqual(["#1", "#2"]);
  });

  it("getPathValues：返回路径下所有值", () => {
    const row = { contact: { phone: "13800138000" }, items: [{ price: "1" }, { price: "2" }] };
    expect(getPathValues(row, tokenizePath("contact.phone"))).toEqual(["13800138000"]);
    expect(getPathValues(row, tokenizePath("items[*].price"))).toEqual(["1", "2"]);
    expect(getPathValues(row, tokenizePath("missing.path"))).toEqual([]);
  });

  it("未命中顶层字段收集", () => {
    const row = { phone: "1", name: "张三", contact: { phone: "2" } };
    const declared = new Set(["phone", "contact"]);
    expect(collectUnmatchedFields(row, declared)).toEqual(["name"]);
  });
});
