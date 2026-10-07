export type AuthMethodInfo = {
  id: string;
  label: string;
  note: string;
  secretName: string;
  envNames: string[];
  available: boolean;
};

export type ProviderInfo = {
  id: string;
  adapter: string;
  displayName: string;
  aliases: string[];
  section: "local" | "cloud";
  description: string;
  authMethods: AuthMethodInfo[];
  defaultBaseUrl: string;
  baseUrlEditable: boolean;
  port: number | null;
  curated: string[];
  defaultPrimary: string;
  keyUrl: string;
};

export type DetectedServer = {
  provider: string;
  baseUrl: string;
  models: string[];
};

export type Catalog = {
  providers: ProviderInfo[];
  servers: DetectedServer[];
  envKeys: string[];
  hardware: unknown[];
  allowProviders: string[];
  cloudWarning: string;
};

export const NO_GPU_NOTE =
  "No GPU detected. Local models will run on the CPU and may be slow. A small model, a server on your network, or a cloud provider may work better.";

export const NO_MATCH =
  "No match. Use 'Other OpenAI-compatible server' for anything that speaks /v1/chat/completions.";
