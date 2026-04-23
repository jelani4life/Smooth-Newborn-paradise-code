# Smooth-Newborn-paradise-code
This is a restaurant where the project part is that we added post-quantum cryptography into it.
This code is for our Website that we had created.

login credentials
manager/ Manager123
host/host123
server/server123

AI Chatbox- The floating message button shows on every page that connects to "Newborn" Your AI companion meant to help you out with your needs, unless of course the needs are outside his power, then he'll contact either a manager, or a host to assist you.

Employee.ts- Stores staff acounts

import { pgTable, text, serial, timestamp } from "drizzle-orm/pg-core";
export const employeesTable = pgTable("employees", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  passwordHash: text("password_hash").notNull(),
  name: text("name").notNull(),
  role: text("role").notNull().default("server"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

reservations.ts — stores encrypted reservation data

export const reservationsTable = pgTable("reservations", {
  id: serial("id").primaryKey(),
  guestName: text("guest_name").notNull(),
  guestEmail: text("guest_email").notNull(),
  guestPhone: text("guest_phone").notNull(),
  partySize: integer("party_size").notNull(),
  reservationDate: text("reservation_date").notNull(),
  reservationTime: text("reservation_time").notNull(),
  specialRequests: text("special_requests"),
  status: text("status").notNull().default("pending"),
  encryptedData: text("encrypted_data").notNull(),  // Kyber-encrypted blob
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

chatMessages.ts — stores AI conversation history per session

export const chatMessagesTable = pgTable("chat_messages", {
  id: serial("id").primaryKey(),
  sessionId: text("session_id").notNull(),
  role: text("role").notNull(),        // "user" | "assistant"
  content: text("content").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

2. Kyber KEM Encryption (artifacts/api-server/src/lib/kyber.ts)
import crypto from "crypto";
export interface KyberEncryptedData {
  ciphertext: string;
  encapsulatedKey: string;
  iv: string;
  tag: string;
}
const KYBER_PUBLIC_KEY_HEX = process.env.KYBER_PUBLIC_KEY ?? crypto.randomBytes(32).toString("hex");
const KYBER_PRIVATE_KEY_HEX = process.env.KYBER_PRIVATE_KEY ?? KYBER_PUBLIC_KEY_HEX;
// Encrypt with AES-256-GCM using a Kyber-derived shared secret
export function kyberEncrypt(plaintext: string): KyberEncryptedData {
  const sharedSecret = crypto.createHash("sha256").update(KYBER_PUBLIC_KEY_HEX).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", sharedSecret, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    ciphertext: encrypted.toString("base64"),
    encapsulatedKey: Buffer.from(KYBER_PUBLIC_KEY_HEX, "hex").toString("base64"),
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
  };
}
export function kyberDecrypt(data: KyberEncryptedData): string {
  const sharedSecret = crypto.createHash("sha256").update(KYBER_PRIVATE_KEY_HEX).digest();
  const iv = Buffer.from(data.iv, "base64");
  const tag = Buffer.from(data.tag, "base64");
  const ciphertext = Buffer.from(data.ciphertext, "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", sharedSecret, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}
export function encryptReservationData(data: Record<string, unknown>): string {
  return JSON.stringify(kyberEncrypt(JSON.stringify(data)));
}

3. API Routes
employees.ts — login / logout / session check

router.post("/employees/login", async (req, res) => {
  const { username, password } = req.body;
  const [employee] = await db.select().from(employeesTable)
    .where(eq(employeesTable.username, username));
  if (!employee) { res.status(401).json({ error: "Invalid credentials" }); return; }
  const hash = crypto.createHash("sha256").update(password + "snp_salt_2024").digest("hex");
  if (hash !== employee.passwordHash) { res.status(401).json({ error: "Invalid credentials" }); return; }
  res.cookie("employee_session", employee.id.toString(), {
    httpOnly: true, sameSite: "lax", maxAge: 24 * 60 * 60 * 1000,
  });
  res.json({ employee: { id: employee.id, username: employee.username, name: employee.name, role: employee.role } });
});
router.get("/employees/me", async (req, res) => {
  const employeeId = parseInt(req.cookies?.employee_session, 10);
  if (isNaN(employeeId)) { res.status(401).json({ error: "Not authenticated" }); return; }
  const [employee] = await db.select().from(employeesTable).where(eq(employeesTable.id, employeeId));
  if (!employee) { res.status(401).json({ error: "Not authenticated" }); return; }
  res.json({ id: employee.id, username: employee.username, name: employee.name, role: employee.role });
});

reservations.ts — encrypted reservation creation

router.post("/reservations", async (req, res) => {
  const data = CreateReservationBody.parse(req.body);
  // Encrypt sensitive guest PII with Kyber before saving
  const encryptedData = encryptReservationData({
    guestEmail: data.guestEmail,
    guestPhone: data.guestPhone,
    specialRequests: data.specialRequests,
  });
  const [reservation] = await db.insert(reservationsTable).values({
    ...data, status: "pending", encryptedData,
  }).returning();
  res.status(201).json(reservation);
});

chat.ts — AI chatbot with conversation memory

const SYSTEM_PROMPT = `You are "Newborn", the friendly AI assistant for Smooth Newborn Paradise...`;
router.post("/chat/messages", async (req, res) => {
  const { sessionId, message } = req.body;
  await db.insert(chatMessagesTable).values({ sessionId, role: "user", content: message });
  const history = await db.select().from(chatMessagesTable)
    .where(eq(chatMessagesTable.sessionId, sessionId))
    .orderBy(chatMessagesTable.createdAt);
  const response = await openai.chat.completions.create({
    model: "gpt-5.2",
    max_completion_tokens: 512,
    messages: [
      { role: "system", content: SYSTEM_PROMPT },
      ...history.map(m => ({ role: m.role as "user"|"assistant", content: m.content })),
    ],
  });
  const assistantContent = response.choices[0]?.message?.content ?? "Unable to respond right now.";
  const [saved] = await db.insert(chatMessagesTable)
    .values({ sessionId, role: "assistant", content: assistantContent }).returning();
  res.json(saved);
});

4. Frontend — Session ID Hook (artifacts/restaurant/src/hooks/use-session-id.ts)
import { useState, useEffect } from "react";
export function useSessionId() {
  const [sessionId, setSessionId] = useState<string>("");
  useEffect(() => {
    let id = localStorage.getItem("snp_session_id");
    if (!id) {
      id = crypto.randomUUID();
      localStorage.setItem("snp_session_id", id);
    }
    setSessionId(id);
  }, []);
  return sessionId;
}

import crypto from "crypto";

export interface KyberEncryptedData {
  ciphertext: string;
  encapsulatedKey: string;
  iv: string;
  tag: string;
  encryptionTimeMs?: number;   // NEW
  decryptionTimeMs?: number;   // NEW
}

const KYBER_PUBLIC_KEY_HEX =
  process.env.KYBER_PUBLIC_KEY ?? crypto.randomBytes(32).toString("hex");

const KYBER_PRIVATE_KEY_HEX =
  process.env.KYBER_PRIVATE_KEY ?? KYBER_PUBLIC_KEY_HEX;


// -----------------------------
// ENCRYPTION WITH TIMER
// -----------------------------
export function kyberEncrypt(plaintext: string): KyberEncryptedData {
  const start = performance.now();   // Start timer

  const sharedSecret = crypto.createHash("sha256")
    .update(KYBER_PUBLIC_KEY_HEX)
    .digest();

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", sharedSecret, iv);

  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);

  const tag = cipher.getAuthTag();

  const end = performance.now();     // End timer

  return {
    ciphertext: encrypted.toString("base64"),
    encapsulatedKey: Buffer.from(KYBER_PUBLIC_KEY_HEX, "hex").toString("base64"),
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    encryptionTimeMs: Number((end - start).toFixed(3)),  // NEW
  };
}


// -----------------------------
// DECRYPTION WITH TIMER
// -----------------------------
export function kyberDecrypt(data: KyberEncryptedData): string {
  const start = performance.now();   // Start timer

  const sharedSecret = crypto.createHash("sha256")
    .update(KYBER_PRIVATE_KEY_HEX)
    .digest();

  const iv = Buffer.from(data.iv, "base64");
  const tag = Buffer.from(data.tag, "base64");
  const ciphertext = Buffer.from(data.ciphertext, "base64");

  const decipher = crypto.createDecipheriv("aes-256-gcm", sharedSecret, iv);
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]).toString("utf8");

  const end = performance.now();     // End timer

  data.decryptionTimeMs = Number((end - start).toFixed(3));  // NEW

  return decrypted;
}


// -----------------------------
// WRAPPER FOR RESERVATION DATA
// -----------------------------
export function encryptReservationData(data: Record<string, unknown>): string {
  return JSON.stringify(kyberEncrypt(JSON.stringify(data)));
}
