import { Router, type IRouter, type Response } from "express";
import { and, desc, eq, ilike, or } from "drizzle-orm";
import {
  AnalyzeAlertParams,
  CreateAlertBody,
  CreateMachineBody,
  ListAlertsQueryParams,
  ListInsightsQueryParams,
  UpdateAlertBody,
  UpdateAlertParams,
  UpdateMachineBody,
  UpdateMachineParams,
} from "@workspace/api-zod";
import {
  alertsTable,
  db,
  insightsTable,
  monitoredMachinesTable,
  type Alert,
} from "@workspace/db";

const router: IRouter = Router();
let seedPromise: Promise<void> | undefined;

const now = () => new Date();
const id = () => crypto.randomUUID();

function sendValidationError(res: Response, message: string) {
  res.status(400).json({ error: message });
}

function toAlert(alert: Alert) {
  return {
    id: alert.id,
    signature: alert.signature,
    signatureId: alert.signatureId,
    classification: alert.classification,
    priority: alert.priority,
    severity: alert.severity,
    sourceIp: alert.sourceIp,
    sourcePort: alert.sourcePort,
    destIp: alert.destIp,
    destPort: alert.destPort,
    protocol: alert.protocol,
    rawLog: alert.rawLog,
    status: alert.status,
    detectedAt: alert.detectedAt.toISOString(),
  };
}

function buildInsight(alert: Alert) {
  const signature = alert.signature.toLowerCase();
  const attackType = signature.includes("sql")
    ? "SQL Injection"
    : signature.includes("scan") || signature.includes("sweep")
      ? "Port Scan"
      : signature.includes("brute") || signature.includes("ssh")
        ? "Brute Force"
        : signature.includes("malware") || signature.includes("trojan")
          ? "Malware Activity"
          : "Suspicious Network Activity";
  const severityWeight = { critical: 92, high: 78, medium: 54, low: 30, info: 12 }[
    alert.severity as "critical" | "high" | "medium" | "low" | "info"
  ] ?? 50;
  const riskScore = Math.min(100, Math.max(5, severityWeight + (5 - alert.priority) * 3));
  const indicators = [alert.sourceIp, alert.destIp, alert.signatureId].filter(Boolean);

  return {
    id: id(),
    alertId: alert.id,
    analysis: `${attackType} pattern detected in the Snort event. The ${alert.protocol} flow from ${alert.sourceIp} to ${alert.destIp} matches a ${alert.severity}-severity detection and warrants containment review.`,
    attackType,
    riskScore,
    confidence: alert.signatureId ? 0.91 : 0.82,
    recommendation:
      riskScore >= 75
        ? "Isolate the destination host, block the source indicator at the edge, and review related events from the last 30 minutes."
        : "Validate the event against expected traffic, then add the indicators to monitoring and review adjacent Snort alerts.",
    indicators,
    modelVersion: "netsentry-local-v1",
    createdAt: now().toISOString(),
  };
}

async function ensureSeedData() {
  if (!seedPromise) {
    seedPromise = (async () => {
      const existingAlerts = await db.select({ id: alertsTable.id }).from(alertsTable).limit(1);
      const existingMachines = await db.select({ id: monitoredMachinesTable.id }).from(monitoredMachinesTable).limit(1);
      if (existingAlerts.length === 0) {
        const base = Date.now();
        const seededAlerts = [
          {
            id: id(),
            signature: "ET SCAN Potential SSH Scan",
            signatureId: "2001219",
            classification: "Attempted Information Leak",
            priority: 2,
            severity: "high",
            sourceIp: "185.220.101.24",
            sourcePort: 41782,
            destIp: "10.0.1.14",
            destPort: 22,
            protocol: "TCP",
            rawLog: "[Priority 2] [Classification: Attempted Information Leak] ET SCAN Potential SSH Scan",
            status: "new",
            detectedAt: new Date(base - 9 * 60 * 1000),
          },
          {
            id: id(),
            signature: "WEB-ATTACKS SQL Injection Attempt",
            signatureId: "2100367",
            classification: "Web Application Attack",
            priority: 1,
            severity: "critical",
            sourceIp: "172.16.4.88",
            sourcePort: 52014,
            destIp: "10.0.2.19",
            destPort: 443,
            protocol: "TCP",
            rawLog: "[Priority 1] [Classification: Web Application Attack] WEB-ATTACKS SQL Injection Attempt",
            status: "analyzed",
            detectedAt: new Date(base - 24 * 60 * 1000),
          },
          {
            id: id(),
            signature: "GPL DNS Suspicious TXT Query",
            signatureId: "2150001",
            classification: "Potentially Bad Traffic",
            priority: 3,
            severity: "medium",
            sourceIp: "10.0.4.32",
            sourcePort: 55321,
            destIp: "8.8.8.8",
            destPort: 53,
            protocol: "UDP",
            rawLog: "[Priority 3] [Classification: Potentially Bad Traffic] GPL DNS Suspicious TXT Query",
            status: "new",
            detectedAt: new Date(base - 47 * 60 * 1000),
          },
          {
            id: id(),
            signature: "ET POLICY Outbound Malware Beacon",
            signatureId: "2027755",
            classification: "Policy Violation",
            priority: 1,
            severity: "critical",
            sourceIp: "10.0.3.7",
            sourcePort: 49210,
            destIp: "91.199.81.12",
            destPort: 8080,
            protocol: "TCP",
            rawLog: "[Priority 1] [Classification: Policy Violation] ET POLICY Outbound Malware Beacon",
            status: "new",
            detectedAt: new Date(base - 2 * 60 * 60 * 1000),
          },
          {
            id: id(),
            signature: "SCAN Nmap SYN Probe",
            signatureId: "122:1:1",
            classification: "Network Scan",
            priority: 3,
            severity: "low",
            sourceIp: "10.0.1.55",
            sourcePort: 4321,
            destIp: "10.0.1.0",
            destPort: null,
            protocol: "TCP",
            rawLog: "[Priority 3] [Classification: Network Scan] SCAN Nmap SYN Probe",
            status: "resolved",
            detectedAt: new Date(base - 5 * 60 * 60 * 1000),
          },
        ];
        await db.insert(alertsTable).values(seededAlerts);
        const analyzed = buildInsight({ ...seededAlerts[1], createdAt: now() });
        await db.insert(insightsTable).values({
          ...analyzed,
          createdAt: new Date(analyzed.createdAt),
        });
      }
      if (existingMachines.length === 0) {
        await db.insert(monitoredMachinesTable).values([
          {
            id: id(),
            ipAddress: "10.0.1.14",
            hostname: "edge-gateway-01",
            department: "Infrastructure",
            os: "Ubuntu 24.04 LTS",
            status: "active",
            notes: "Primary ingress gateway monitored by Snort sensor.",
          },
          {
            id: id(),
            ipAddress: "10.0.2.19",
            hostname: "payments-api",
            department: "Engineering",
            os: "Ubuntu 22.04 LTS",
            status: "active",
            notes: "Customer-facing API host.",
          },
          {
            id: id(),
            ipAddress: "10.0.3.7",
            hostname: "finance-laptop-07",
            department: "Finance",
            os: "Windows 11",
            status: "maintenance",
            notes: "Pending endpoint agent update.",
          },
        ]);
      }
    })().catch((error) => {
      seedPromise = undefined;
      throw error;
    });
  }
  await seedPromise;
}

router.get("/alerts", async (req, res) => {
  await ensureSeedData();
  const parsed = ListAlertsQueryParams.safeParse(req.query);
  if (!parsed.success) return sendValidationError(res, "Invalid alert filters");
  const { limit = 50, severity, status, search } = parsed.data;
  const filters = [];
  if (severity) filters.push(eq(alertsTable.severity, severity));
  if (status) filters.push(eq(alertsTable.status, status));
  if (search) {
    filters.push(
      or(
        ilike(alertsTable.signature, `%${search}%`),
        ilike(alertsTable.sourceIp, `%${search}%`),
        ilike(alertsTable.destIp, `%${search}%`),
      ),
    );
  }
  const rows = await db
    .select()
    .from(alertsTable)
    .where(filters.length ? and(...filters) : undefined)
    .orderBy(desc(alertsTable.detectedAt))
    .limit(limit);
  res.json(rows.map(toAlert));
});

router.post("/alerts", async (req, res) => {
  const parsed = CreateAlertBody.safeParse(req.body);
  if (!parsed.success) return sendValidationError(res, "Invalid alert payload");
  const data = parsed.data;
  const [created] = await db.insert(alertsTable).values({
    id: id(),
    signature: data.signature,
    signatureId: data.signatureId ?? "",
    classification: data.classification ?? "",
    priority: data.priority ?? 2,
    severity: data.severity ?? "medium",
    sourceIp: data.sourceIp,
    sourcePort: data.sourcePort ?? null,
    destIp: data.destIp,
    destPort: data.destPort ?? null,
    protocol: data.protocol ?? "TCP",
    rawLog: data.rawLog ?? null,
    status: data.status ?? "new",
    detectedAt: data.detectedAt ? new Date(data.detectedAt) : now(),
  }).returning();
  res.status(201).json(toAlert(created));
});

router.patch("/alerts/:id", async (req, res) => {
  const params = UpdateAlertParams.safeParse(req.params);
  const body = UpdateAlertBody.safeParse(req.body);
  if (!params.success || !body.success) return sendValidationError(res, "Invalid alert update");
  const [updated] = await db.update(alertsTable).set(body.data).where(eq(alertsTable.id, params.data.id)).returning();
  if (!updated) return res.status(404).json({ error: "Alert not found" });
  res.json(toAlert(updated));
});

router.delete("/alerts/:id", async (req, res) => {
  const [deleted] = await db.delete(alertsTable).where(eq(alertsTable.id, req.params.id)).returning({ id: alertsTable.id });
  if (!deleted) return res.status(404).json({ error: "Alert not found" });
  await db.delete(insightsTable).where(eq(insightsTable.alertId, deleted.id));
  return res.status(204).send();
});

router.post("/alerts/:id/analyze", async (req, res) => {
  const params = AnalyzeAlertParams.safeParse(req.params);
  if (!params.success) return sendValidationError(res, "Invalid alert id");
  const [alert] = await db.select().from(alertsTable).where(eq(alertsTable.id, params.data.id)).limit(1);
  if (!alert) return res.status(404).json({ error: "Alert not found" });
  const insight = buildInsight(alert);
  await db.insert(insightsTable).values({ ...insight, createdAt: new Date(insight.createdAt) });
  await db.update(alertsTable).set({ status: "analyzed" }).where(eq(alertsTable.id, alert.id));
  res.json(insight);
});

router.get("/insights", async (req, res) => {
  await ensureSeedData();
  const parsed = ListInsightsQueryParams.safeParse(req.query);
  if (!parsed.success) return sendValidationError(res, "Invalid insight filters");
  const rows = await db.select().from(insightsTable).orderBy(desc(insightsTable.createdAt)).limit(parsed.data.limit ?? 50);
  res.json(rows.map((row) => ({ ...row, createdAt: row.createdAt.toISOString() })));
});

router.get("/machines", async (_req, res) => {
  await ensureSeedData();
  const rows = await db.select().from(monitoredMachinesTable).orderBy(desc(monitoredMachinesTable.createdAt));
  res.json(rows.map((row) => ({ ...row, createdAt: row.createdAt.toISOString() })));
});

router.post("/machines", async (req, res) => {
  const parsed = CreateMachineBody.safeParse(req.body);
  if (!parsed.success) return sendValidationError(res, "Invalid machine payload");
  const data = parsed.data;
  const [created] = await db.insert(monitoredMachinesTable).values({
    id: id(),
    ipAddress: data.ipAddress,
    hostname: data.hostname,
    department: data.department ?? null,
    os: data.os ?? null,
    status: data.status ?? "active",
    notes: data.notes ?? null,
  }).returning();
  res.status(201).json({ ...created, createdAt: created.createdAt.toISOString() });
});

router.patch("/machines/:id", async (req, res) => {
  const params = UpdateMachineParams.safeParse(req.params);
  const body = UpdateMachineBody.safeParse(req.body);
  if (!params.success || !body.success) return sendValidationError(res, "Invalid machine update");
  const [updated] = await db.update(monitoredMachinesTable).set(body.data).where(eq(monitoredMachinesTable.id, params.data.id)).returning();
  if (!updated) return res.status(404).json({ error: "Machine not found" });
  res.json({ ...updated, createdAt: updated.createdAt.toISOString() });
});

router.delete("/machines/:id", async (req, res) => {
  const [deleted] = await db.delete(monitoredMachinesTable).where(eq(monitoredMachinesTable.id, req.params.id)).returning({ id: monitoredMachinesTable.id });
  if (!deleted) return res.status(404).json({ error: "Machine not found" });
  return res.status(204).send();
});

router.get("/dashboard/summary", async (_req, res) => {
  await ensureSeedData();
  const alerts = await db.select().from(alertsTable).orderBy(desc(alertsTable.detectedAt)).limit(100);
  const insights = await db.select().from(insightsTable).orderBy(desc(insightsTable.createdAt)).limit(100);
  const severityCounts = alerts.reduce<Record<string, number>>((acc, alert) => {
    acc[alert.severity] = (acc[alert.severity] ?? 0) + 1;
    return acc;
  }, {});
  const attackTypes = Object.entries(insights.reduce<Record<string, number>>((acc, insight) => {
    acc[insight.attackType] = (acc[insight.attackType] ?? 0) + 1;
    return acc;
  }, {})).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count).slice(0, 6);
  const avgRiskScore = insights.length ? insights.reduce((sum, row) => sum + row.riskScore, 0) / insights.length : 0;
  const avgConfidence = insights.length ? insights.reduce((sum, row) => sum + row.confidence, 0) / insights.length : 0;
  res.json({
    totalAlerts: alerts.length,
    highSeverity: alerts.filter((alert) => alert.severity === "critical" || alert.severity === "high").length,
    analyzed: alerts.filter((alert) => alert.status === "analyzed").length,
    insights: insights.length,
    avgRiskScore: Number(avgRiskScore.toFixed(1)),
    avgConfidence: Number(avgConfidence.toFixed(2)),
    severityCounts,
    attackTypes,
  });
});

export default router;