import typescript from "@rollup/plugin-typescript";
import resolve from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";

export default {
  input: "src/index.ts",
  output: [
    { file: "dist/index.js", format: "es" },
    { file: "dist/index.cjs", format: "cjs", exports: "named" }
  ],
  plugins: [
    resolve({ preferBuiltins: true }),
    commonjs(),
    typescript({ tsconfig: "./tsconfig.json", declaration: false })
  ]
};
