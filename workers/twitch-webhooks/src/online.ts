import { createError, defineEventHandler, getHeaders, readBody, readRawBody } from 'h3'
import { verifyEventMessage } from 'twitch'
import * as v from 'valibot'

const headerValidator = v.pipe(
  v.string(),
  v.trim(),
  v.nonEmpty()
)

const headersSchema = v.pipe(
  v.object({
    // Any format
    'twitch-eventsub-message-id': headerValidator,
    // '0', '1', etc.
    'twitch-eventsub-message-retry': headerValidator,
    // 'notification' | 'webhook_callback_verification' | 'revocation'
    'twitch-eventsub-message-type': headerValidator,
    // 'sha256=<signature>' (HMAC SHA256)
    'twitch-eventsub-message-signature': headerValidator,
    // RFC3339, 2021-07-15T17:37:21.000Z
    'twitch-eventsub-message-timestamp': headerValidator,
    // The subscription type you subscribed to. For example, channel.follow
    'twitch-eventsub-subscription-type': headerValidator,
    // '1', etc.
    'twitch-eventsub-subscription-version': headerValidator
  }),

  v.transform((value) => ({
    messageId: value['twitch-eventsub-message-id'],
    messageRetry: value['twitch-eventsub-message-retry'],
    messageType: value['twitch-eventsub-message-type'],
    messageSignature: value['twitch-eventsub-message-signature'],
    messageTimestamp: value['twitch-eventsub-message-timestamp'],
    subscriptionType: value['twitch-eventsub-subscription-type'],
    subscriptionVersion: value['twitch-eventsub-subscription-version']
  }))
)

function handleError(statusCode: number, logMessage: string, ...args: unknown[]) {
  console.error(logMessage, ...args)

  return createError({
    status: statusCode
  })
}

export default defineEventHandler(async (event) => {
  const { TWITCH_APP_SECRET } = event.context.cloudflare.env

  // Check if the secret is defined
  if (TWITCH_APP_SECRET === undefined) {
    return handleError(500, 'TWITCH_APP_SECRET is not defined')
  }

  const headers = getHeaders(event)

  /**
   * @see {@link https://dev.twitch.tv/docs/eventsub/handling-webhook-events/#list-of-request-headers}
   */
  const { success, output, issues } = v.safeParse(headersSchema, headers)

  if (success === false) {
    return handleError(403, 'Headers validation failed', issues)
  }

  const rawBody = await readRawBody(event)

  if (rawBody === undefined) {
    return handleError(403, 'Failed to read the raw body')
  }

  const isVerified = await verifyEventMessage({
    body: rawBody,
    messageId: output.messageId,
    messageTimestamp: output.messageTimestamp,
    messageSignature: output.messageSignature,
    secret: TWITCH_APP_SECRET,
  })

  if (isVerified === false) {
    return handleError(403, 'Failed to verify the event message')
  }

  // TODO: Implement the rest of the logic
  // const body = await readBody(event)

  return {
    verified: isVerified
  }
})
