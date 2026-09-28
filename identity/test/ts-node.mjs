// `node --test` doesn't pass `--loader` to its workers, but it does pass `--import`.
import { register } from "node:module";
import { pathToFileURL } from "node:url";

register("ts-node/esm", pathToFileURL("./"));
