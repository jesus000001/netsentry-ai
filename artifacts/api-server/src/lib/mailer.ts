import nodemailer from "nodemailer";

const smtpHost = process.env.SMTP_HOST;
const smtpPort = Number(process.env.SMTP_PORT ?? 465);
const smtpSecure = (process.env.SMTP_SECURE ?? "true") === "true";
const smtpUser = process.env.SMTP_USER;
const smtpPass = process.env.SMTP_PASS;
const alertEmail = process.env.ALERT_EMAIL;

if (!smtpHost || !smtpUser || !smtpPass || !alertEmail) {
  throw new Error("SMTP configuration is incomplete");
}

const transporter = nodemailer.createTransport({
  host: smtpHost,
  port: smtpPort,
  secure: smtpSecure,
  auth: {
    user: smtpUser,
    pass: smtpPass,
  },
});

export async function sendAlertEmail(alert: {
  id: string;
  signature: string;
  severity: string;
  classification: string;
  sourceIp: string;
  sourcePort: number | null;
  destIp: string;
  destPort: number | null;
  protocol: string;
  detectedAt: Date | string;
}) {
  await transporter.sendMail({
    from: smtpUser,
    to: alertEmail,
    subject: `[NetSentry] ${alert.severity.toUpperCase()} - ${alert.signature}`,
    text: `
NetSentry Security Alert

Signature: ${alert.signature}
Severity: ${alert.severity}
Classification: ${alert.classification}

Source: ${alert.sourceIp}:${alert.sourcePort ?? ""}
Destination: ${alert.destIp}:${alert.destPort ?? ""}
Protocol: ${alert.protocol}

Detected at: ${alert.detectedAt}
Alert ID: ${alert.id}
    `.trim(),
  });
}
