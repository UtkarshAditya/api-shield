import type { Role } from "@/api/schemas";

export type Permission =
  | "alerts.triage"
  | "rules.edit"
  | "scans.run"
  | "settings.edit"
  | "mode.switch"
  | "data.purge"
  | "users.manage";

const grants: Record<Role, Permission[]> = {
  admin: ["alerts.triage", "rules.edit", "scans.run", "settings.edit", "mode.switch", "data.purge", "users.manage"],
  analyst: ["alerts.triage", "rules.edit", "scans.run"],
  viewer: [],
};

export function can(role: Role | undefined, permission: Permission) {
  return !!role && grants[role].includes(permission);
}

export const roleLabel: Record<Role, string> = { admin: "Admin", analyst: "Analyst", viewer: "Viewer" };
