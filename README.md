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

1. Install the library
In the Smooth Newborn Paradise project:

pnpm --filter @workspace/api-server add @noble/post-quantum

2. Replace artifacts/api-server/src/lib/kyber.ts
import crypto from "crypto";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
export interface KyberEncryptedData {
  ciphertext: string;       // AES-256-GCM ciphertext (base64)
  encapsulatedKey: string;  // ML-KEM-768 KEM ciphertext (base64) — the real one
  iv: string;               // AES-GCM IV (base64)
  tag: string;              // AES-GCM auth tag (base64)
  encryptionTimeMs?: number;
  decryptionTimeMs?: number;
  kemTimeMs?: number;
  aesTimeMs?: number;
}
function loadKeypair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const pk = process.env.KYBER_PUBLIC_KEY;
  const sk = process.env.KYBER_PRIVATE_KEY;
  if (pk && sk) {
    return {
      publicKey: new Uint8Array(Buffer.from(pk, "base64")),
      secretKey: new Uint8Array(Buffer.from(sk, "base64")),
    };
  }
  console.warn(
    "[kyber] KYBER_PUBLIC_KEY / KYBER_PRIVATE_KEY are not set. " +
      "Generating an EPHEMERAL keypair. Data encrypted before a restart will be UNDECRYPTABLE. " +
      "Run scripts/generate-kyber-keypair.ts once and set the env vars before going to production."
  );
  return ml_kem768.keygen();
}
const { publicKey: KYBER_PUBLIC_KEY, secretKey: KYBER_PRIVATE_KEY } = loadKeypair();
export function kyberEncrypt(plaintext: string): KyberEncryptedData {
  const totalStart = performance.now();
  // 1. KEM encapsulate against the public key → 32-byte shared secret + KEM ciphertext.
  const kemStart = performance.now();
  const { cipherText: kemCt, sharedSecret } = ml_kem768.encapsulate(KYBER_PUBLIC_KEY);
  const kemTimeMs = Number((performance.now() - kemStart).toFixed(3));
  // 2. AES-256-GCM with the shared secret as the key.
  const aesStart = performance.now();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", Buffer.from(sharedSecret), iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  const aesTimeMs = Number((performance.now() - aesStart).toFixed(3));
  return {
    ciphertext: encrypted.toString("base64"),
    encapsulatedKey: Buffer.from(kemCt).toString("base64"),
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    encryptionTimeMs: Number((performance.now() - totalStart).toFixed(3)),
    kemTimeMs,
    aesTimeMs,
  };
}
export function kyberDecrypt(data: KyberEncryptedData): string {
  const totalStart = performance.now();
  // 1. KEM decapsulate to recover the same shared secret.
  const kemStart = performance.now();
  const kemCt = new Uint8Array(Buffer.from(data.encapsulatedKey, "base64"));
  const sharedSecret = ml_kem768.decapsulate(kemCt, KYBER_PRIVATE_KEY);
  const kemTimeMs = Number((performance.now() - kemStart).toFixed(3));
  // 2. AES-256-GCM decrypt.
  const aesStart = performance.now();
  const iv = Buffer.from(data.iv, "base64");
  const tag = Buffer.from(data.tag, "base64");
  const ciphertext = Buffer.from(data.ciphertext, "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", Buffer.from(sharedSecret), iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  const aesTimeMs = Number((performance.now() - aesStart).toFixed(3));
  data.decryptionTimeMs = Number((performance.now() - totalStart).toFixed(3));
  data.kemTimeMs = kemTimeMs;
  data.aesTimeMs = aesTimeMs;
  return plaintext;
}
export function encryptReservationData(data: Record<string, unknown>): string {
  return JSON.stringify(kyberEncrypt(JSON.stringify(data)));
}
export function decryptReservationData(json: string): Record<string, unknown> {
  return JSON.parse(kyberDecrypt(JSON.parse(json) as KyberEncryptedData));
}

Public API (kyberEncrypt, kyberDecrypt, encryptReservationData) is unchanged, so your existing reservations.ts route keeps working. The KyberEncryptedData interface gains kemTimeMs and aesTimeMs alongside the existing encryptionTimeMs / decryptionTimeMs you already added.

3. Add a one-shot keypair generator: scripts/src/generate-kyber-keypair.ts
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
const { publicKey, secretKey } = ml_kem768.keygen();
console.log("KYBER_PUBLIC_KEY=" + Buffer.from(publicKey).toString("base64"));
console.log("KYBER_PRIVATE_KEY=" + Buffer.from(secretKey).toString("base64"));

Run it once: pnpm --filter @workspace/scripts exec tsx src/generate-kyber-keypair.ts

Copy the two lines it prints into your project's Secrets (env vars). Treat KYBER_PRIVATE_KEY like a password — never commit it, never expose it to the browser.

4. (Optional) Show the timings on the reservation confirmation
Your existing route returns the saved reservation row, which doesn't include the timings. If you want them visible, change the route to something like:

router.post("/reservations", async (req, res) => {
  const data = CreateReservationBody.parse(req.body);
  const enc = kyberEncrypt(JSON.stringify({
    guestEmail: data.guestEmail,
    guestPhone: data.guestPhone,
    specialRequests: data.specialRequests,
  }));
  const [reservation] = await db.insert(reservationsTable).values({
    ...data,
    status: "pending",
    encryptedData: JSON.stringify(enc),
  }).returning();
  res.status(201).json({
    reservation,
    crypto: {
      algorithm: "ML-KEM-768 + AES-256-GCM",
      totalMs: enc.encryptionTimeMs,
      kemEncapsulateMs: enc.kemTimeMs,
      aesGcmMs: enc.aesTimeMs,
      kemCiphertextBytes: Buffer.from(enc.encapsulatedKey, "base64").length,
    },
  });
});
