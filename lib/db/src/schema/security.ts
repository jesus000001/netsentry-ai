import {
  integer,
  real,
  text,
  timestamp,
  pgTable,
} from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const alertsTable = pgTable("alerts", {
  id: text("id").primaryKey(),
  signature: text("signature").notNull(),
  signatureId: text("signature_id").notNull().default(""),
  classification: text("classification").notNull().default(""),
  priority: integer("priority").notNull().default(2),
  severity: text("severity").notNull().default("medium"),
  sourceIp: text("source_ip").notNull(),
  sourcePort: integer("source_port"),
  destIp: text("dest_ip").notNull(),
  destPort: integer("dest_port"),
  protocol: text("protocol").notNull().default("TCP"),
  rawLog: text("raw_log"),
  status: text("status").notNull().default("new"),
  detectedAt: timestamp("detected_at", { withTimezone: true }).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const insightsTable = pgTable("insights", {
  id: text("id").primaryKey(),
  alertId: text("alert_id").notNull(),
  analysis: text("analysis").notNull(),
  attackType: text("attack_type").notNull(),
  riskScore: integer("risk_score").notNull(),
  confidence: real("confidence").notNull(),
  recommendation: text("recommendation").notNull(),
  indicators: text("indicators").array().notNull().default([]),
  modelVersion: text("model_version").notNull().default("base44-sec-v1"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const monitoredMachinesTable = pgTable("monitored_machines", {
  id: text("id").primaryKey(),
  ipAddress: text("ip_address").notNull(),
  hostname: text("hostname").notNull(),
  department: text("department"),
  os: text("os"),
  status: text("status").notNull().default("active"),
  notes: text("notes"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const insertAlertSchema = createInsertSchema(alertsTable).omit({
  id: true,
  createdAt: true,
});
export const insertInsightSchema = createInsertSchema(insightsTable).omit({
  id: true,
  createdAt: true,
});
export const insertMachineSchema = createInsertSchema(monitoredMachinesTable).omit({
  id: true,
  createdAt: true,
});

export type Alert = typeof alertsTable.$inferSelect;
export type InsertAlert = z.infer<typeof insertAlertSchema>;
export type Insight = typeof insightsTable.$inferSelect;
export type InsertInsight = z.infer<typeof insertInsightSchema>;
export type MonitoredMachine = typeof monitoredMachinesTable.$inferSelect;
export type InsertMachine = z.infer<typeof insertMachineSchema>;