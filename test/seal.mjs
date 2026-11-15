// Seals {"<field>": "<value>"} to the form in a link: node test/seal.mjs LINK FIELD VALUE
import { tokenFrom, openSpec, seal } from "../sealed.js";
const [link, field, value] = process.argv.slice(2);
const u = new URL(link);
const { spec, rawKey } = await openSpec(tokenFrom(u.hash, u.search));
process.stdout.write(await seal(spec, rawKey, { [field]: value }));
