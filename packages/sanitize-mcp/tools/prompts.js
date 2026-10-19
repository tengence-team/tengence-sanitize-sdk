'use strict';
/**
 * Tengence sanitize MCP Prompt templates (@tengence/sanitize-mcp/tools/prompts)
 * ============================================================================
 * Each prompt = { name, title, description, argsSchema, run(args) }.
 * run() returns { description, messages: [{ role, content: { type:'text', text } }] }
 * — the shape of GetPromptResult consumed by registerPrompt.
 *
 * Prompts are user-controlled: the client lists them via prompts/list and the
 * user explicitly invokes one (e.g. a slash command). They encode proven call
 * sequences so an AI client doesn't reinvent the workflow each time.
 */

const { z } = require('zod');

const configArg = z.string().describe('absolute path to sanitize.config.json');

function msg(text) {
  return [{ role: 'user', content: { type: 'text', text } }];
}

const prompts = [
  {
    name: 'sanitize_setup_config',
    title: '生成/审阅脱敏配置',
    description:
      '为指定业务字段生成或审阅 sanitize.config.json（字段与脱敏方式用户自定义）。先读 sanitize://config-schema，再产出配置文件路径。',
    argsSchema: z.object({
      fields: z
        .string()
        .describe('要脱敏的字段与方式描述，例如 "phone 用 hash、id_card 用 mask（留前3后4）、contact.phone 与 items[*].price 用 encrypt"'),
      output: z.string().describe('配置文件落盘路径，例如 ~/sanitize/sanitize.config.json'),
    }),
    run(args) {
      return {
        description: '生成或审阅一份 sanitize.config.json',
        messages: msg(
          `为以下业务字段准备一份 sanitize.config.json：\n${args.fields}\n` +
            `1) 先读资源 sanitize://config-schema 了解字段路径与规则参数写法；\n` +
            `2) 生成配置文件并写入 ${args.output}（仅字段声明与参数，密钥一律用环境变量名引用，禁止把密钥写进文件或参数）；\n` +
            `3) 用 sanitize_config_info(config=${args.output}) 校验，向用户汇报规则摘要与 configFingerprint。`
        ),
      };
    },
  },
  {
    name: 'sanitize_desensitize_file',
    title: '文件脱敏完整流程',
    description:
      '对一份数据文件跑完整脱敏流程：校验配置 → dry-run 预览（确认命中与未命中字段）→ 执行脱敏 →（可选）上传。',
    argsSchema: z.object({
      config: configArg,
      input: z.string().describe('输入数据文件路径（CSV/JSON/JSONL/XLSX）'),
      output: z.string().describe('脱敏输出文件路径'),
      upload: z
        .string()
        .optional()
        .describe('脱敏后是否上传到批量推送接口："true"/"false"（默认 "false"）'),
      push_url: z.string().optional().describe('上传接口覆盖（默认 https://api.tengence.com/v1/push/data）'),
    }),
    run(args) {
      const upload = args.upload === 'true';
      return {
        description: '一份数据文件从预览到脱敏（到上传）的完整流程',
        messages: msg(
          `对文件 ${args.input} 执行完整脱敏流程（上传=${upload ? '是' : '否'}）。\n` +
            `1) sanitize_config_info(config=${args.config}) 校验配置；\n` +
            `2) sanitize_dry_run(config, input) 预览——确认每个声明字段 hits>0，` +
            `若出现 unmatchedFields 先与用户确认补配，不要直接脱敏；\n` +
            `3) sanitize_file(config, input, output=${args.output}) 执行脱敏，汇报 batchId/行数/告警/审计路径；\n` +
            (upload
              ? `4) sanitize_upload(config, input=${args.output}${args.push_url ? `, push_url=${args.push_url}` : ''}) 上传（apiKey 来自环境变量），汇报 accepted/rejected。\n`
              : '') +
            `全程不要输出任何原文；如需查看结果请提示用户打开本地输出文件。`
        ),
      };
    },
  },
  {
    name: 'sanitize_verify_audit',
    title: '审计核对',
    description:
      '核对本地审计：列出/读取审计记录，检查未命中字段与上传结果，输出合规小结（无明文）。',
    argsSchema: z.object({
      dir: z.string().optional().describe('审计目录（默认 ~/.tengence/sanitize/audits）'),
      batch_id: z.string().optional().describe('只看某批次（默认全部）'),
    }),
    run(args) {
      return {
        description: '审计记录核对与合规小结',
        messages: msg(
          `核对本地脱敏审计（dir=${args.dir || '默认'}，batch=${args.batch_id || '全部'}）。\n` +
            `1) 用 sanitize_audit_list 列出记录，或读资源 sanitize://audit/{batchId} 看单条详情；\n` +
            `2) 检查：unmatchedFields 是否为空、errorRows/warnings 是否异常、uploadResult 的 accepted/rejected；\n` +
            `3) 输出小结：批次数、总行数、命中字段、未命中字段、上传结果；必要时用 sanitize_audit_export 导出合规举证文件。\n` +
            `全程只汇报统计，不输出任何原文。`
        ),
      };
    },
  },
];

module.exports = { prompts };
