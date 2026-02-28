import { error, type RequestHandler } from "@sveltejs/kit";
import { env } from "$env/dynamic/private";
import { createHmac, timingSafeEqual } from "node:crypto";
import z from "zod";

const parseJson = z
  .string()
  .min(1)
  .transform((s) => JSON.parse(s));

const webhookValidator = z.object({
  action: z.string().min(1).optional(),
  issue: z
    .object({
      title: z.string().min(1),
      number: z.coerce.number().positive()
    })
    .optional(),
  repository: z
    .object({
      name: z.string().min(1),
      full_name: z.string().min(1)
    })
    .optional()
});

type WebhookRequest = z.infer<typeof webhookValidator>;

async function handleWebhookRequest(request: WebhookRequest) {
  if (
    !request.issue ||
    request.action != "opened" ||
    request.repository?.full_name != "bartoostveen/ViTune"
  )
    return;

  try {
    let response = await fetch(
      `https://api.github.com/repos/${request.repository.full_name}/issues/${request.issue.number}`,
      {
        method: "PATCH",
        headers: {
          Accept: "application/vnd.github+json",
          Authorization: `Bearer ${env.GH_API_KEY!}`,
          "X-GitHub-Api-Version": "2022-11-28"
        },
        body: JSON.stringify({
          state: "closed"
        })
      }
    );
    if (!response.ok) {
      console.error("Response from close request was", response);
    }

    response = await fetch(
      `https://api.github.com/repos/${request.repository.full_name}/issues/${request.issue.number}/comments`,
      {
        method: "POST",
        headers: {
          Accept: "application/vnd.github+json",
          Authorization: `Bearer ${env.GH_API_KEY!}`,
          "X-GitHub-Api-Version": "2022-11-28"
        },
        body: JSON.stringify({
          body: `
This issue has been automatically closed due to ViTune not being maintained anymore.
Issues are still open for the sake of handling critical security issues, if there are any.

So, if you **really** believe this issue should not be closed, please reopen, and I'll get back to you as soon as possible.
PLEASE NOTE: sending a message that the issue can be reopened DOES NOT magically reopen! I won't see your message on this repository unless you tap the reopen button.

Thank you for understanding.
                `
        })
      }
    );
    if (!response.ok) {
      console.error("Response from comment request was", response);
    }
  } catch (e) {
    console.error(e);
  }
}

const prefix = "sha256=";
const subscribedEvents = ["issues", "ping"];

function verifySignature(
  payload: string,
  webhookSecret: string,
  webhookSignature: string
): boolean {
  if (webhookSignature.startsWith(prefix)) {
    webhookSignature = webhookSignature.slice(prefix.length);
  }
  const signature = createHmac("sha256", webhookSecret).update(payload).digest("hex");

  try {
    return timingSafeEqual(Buffer.from(webhookSignature), Buffer.from(signature));
  } catch (e) {
    console.error(e);
    return false;
  }
}

export const POST: RequestHandler = async ({ request }) => {
  const blob = await (await request.blob()).text();
  const webhookSignature = request.headers.get("X-Hub-Signature-256") ?? error(400, "bad request");
  if (!verifySignature(blob, env.GH_WEBHOOK_SECRET!, webhookSignature)) error(403, "unauthorized");

  const eventType = request.headers.get("X-GitHub-Event") ?? error(400, "invalid event type");
  if (!subscribedEvents.includes(eventType)) error(400, "not subscribed to such event");

  try {
    const json: WebhookRequest = await parseJson.pipe(webhookValidator).decodeAsync(blob);
    handleWebhookRequest(json);
  } catch (e) {
    console.error(e, "-- received body --", blob);
    error(400, "bad request body");
  }
  return new Response("ok");
};
