// Realistic sample logs (anonymised) used by the "Load sample" button and tests/run.mjs.

const utf8len = (s) => new TextEncoder().encode(s).length;
const W = (ts, ch, dir, data) =>
  `TID: [-1234] [] [2026-10-14 10:15:${ts}]  DEBUG {org.apache.synapse.transport.http.wire} - ${ch} ${dir} "${data}" {org.apache.synapse.transport.http.wire}`;
const CRLF = '[\\r][\\n]';

// ── (a) Inbound WhatsApp "hi" webhook — plain-text WSO2 logs, http.wire chunked body + LogMediator
const waBody = JSON.stringify({
  object: 'whatsapp_business_account',
  entry: [{
    id: '104857362910483',
    changes: [{
      field: 'messages',
      value: {
        messaging_product: 'whatsapp',
        metadata: { display_phone_number: '923111222333', phone_number_id: '110293847561029' },
        contacts: [{ profile: { name: 'Ali' }, wa_id: '923001234567' }],
        messages: [{ from: '923001234567', id: 'wamid.HBgMOTIzMDAxMjM0NTY3FQIAEhgUM0E', timestamp: '1792066501', type: 'text', text: { body: 'hi' } }],
      },
    }],
  }],
});
const part1 = waBody.slice(0, 120);
const part2 = waBody.slice(120);
const L = 'HTTP-Listener I/O dispatcher-21';

export const SAMPLE_INBOUND = [
  `TID: [-1234] [] [2026-10-14 10:15:01,102]  INFO {org.apache.synapse.transport.passthru.SourceHandler} - Connection established from 157.240.9.12 {org.apache.synapse.transport.passthru.SourceHandler}`,
  W('01,118', L, '>>', `POST /WABA/menu HTTP/1.1${CRLF}`),
  W('01,118', L, '>>', `Host: api.jazzcash-gw.example.com${CRLF}`),
  W('01,118', L, '>>', `Content-Type: application/json${CRLF}`),
  W('01,118', L, '>>', `User-Agent: facebookexternalua${CRLF}`),
  W('01,118', L, '>>', `X-Hub-Signature-256: sha256=8f1c0a77d2b4e6f0a9c3b1d5e7f9a2c4b6d8e0f1a3c5e7b9d1f3a5c7e9b1d3f5${CRLF}`),
  W('01,118', L, '>>', `Transfer-Encoding: chunked${CRLF}`),
  W('01,118', L, '>>', CRLF),
  W('01,119', L, '>>', `${utf8len(part1).toString(16)}${CRLF}`),
  W('01,119', L, '>>', `${part1}${CRLF}`),
  W('01,120', L, '>>', `${utf8len(part2).toString(16)}${CRLF}`),
  W('01,120', L, '>>', `${part2}${CRLF}`),
  W('01,120', L, '>>', `0${CRLF}`),
  W('01,120', L, '>>', CRLF),
  `TID: [-1234] [] [2026-10-14 10:15:01,135]  INFO {org.apache.synapse.mediators.builtin.LogMediator} - LOG_TYPE = EVENT_LOG_REQUEST, CORRELATION_ID = 7d3f9e2a-41c6-4b0e-9a55-2f8c1d6e4b90, CHANNEL = WHATSAPP, EVENT_LOG_REQUEST = {"msisdn":"923001234567","channel":"WHATSAPP","event":"INBOUND_MESSAGE","request":{"type":"text","text":"hi","context":{"session":{"id":"S-55102","state":"MAIN_MENU","lang":"en"},"device":{"platform":"whatsapp","version":"2.24"}}},"meta":{"receivedAt":"2026-10-14T10:15:01.118Z","wamid":"wamid.HBgMOTIzMDAxMjM0NTY3FQIAEhgUM0E"}} {org.apache.synapse.mediators.builtin.LogMediator}`,
  `TID: [-1234] [] [2026-10-14 10:15:01,141]  INFO {org.apache.synapse.mediators.builtin.LogMediator} - Raw = {\\"msisdn\\":\\"923001234567\\",\\"txnId\\":\\"TX-20261014-0001\\",\\"step\\":\\"MENU_LOOKUP\\"} {org.apache.synapse.mediators.builtin.LogMediator}`,
  `TID: [-1234] [] [2026-10-14 10:15:01,160]  WARN {org.apache.synapse.transport.passthru.TargetHandler} - Session cache miss for msisdn, creating new session {org.apache.synapse.transport.passthru.TargetHandler}`,
  W('01,201', L, '<<', `HTTP/1.1 200 OK${CRLF}`),
  W('01,201', L, '<<', `Content-Type: application/json${CRLF}`),
  W('01,201', L, '<<', `Content-Length: 15${CRLF}`),
  W('01,201', L, '<<', CRLF),
  W('01,201', L, '<<', `{"status":"OK"}`),
].join('\n');

// ── (b) Outbound Infobip call — NDJSON (one line is truncated → invalid JSON)
const j = (o) => JSON.stringify(o);
const base = (t, level, logger, message, extra = {}) => ({ '@timestamp': `2026-10-14T10:15:${t}Z`, level, logger, thread: 'PassThroughMessageProcessor-41', message, correlationId: '7d3f9e2a-41c6-4b0e-9a55-2f8c1d6e4b90', ...extra });
const infobipResp = { messages: [{ to: '923001234567', messageCount: 1, messageId: 'a8c1e2f0-5b7d-4c3e-9f1a-6d2b8e4c0a17', status: { groupId: 5, groupName: 'REJECTED', id: 25, name: 'REJECTED_FREE_TRIAL_EXCEEDED', description: 'Free trial exceeded' } }] };
const O = 'http-outgoing-420';

export const SAMPLE_OUTBOUND = [
  j(base('01.210', 'INFO', 'org.apache.synapse.mediators.builtin.LogMediator', `API_NAME = JAZZCASH_WHATSAPP_VALIDATE_PIN_FLOW, STEP = SEND_PIN_PROMPT, REQUEST_BODY = ${j({ msisdn: '923001234567', mpin: '4821', flow: 'VALIDATE_PIN' })}`)),
  j(base('01.214', 'DEBUG', 'org.apache.http.headers', `${O} >> POST /whatsapp/1/message/template HTTP/1.1`)),
  j(base('01.214', 'DEBUG', 'org.apache.http.headers', `${O} >> Host: xk9p2.api.infobip.com`)),
  j(base('01.214', 'DEBUG', 'org.apache.http.headers', `${O} >> Authorization: App 3f9a6c1e8b2d4f7a0c5e9b1d3f6a8c2e-7b4d1f9a`)),
  j(base('01.214', 'DEBUG', 'org.apache.http.headers', `${O} >> Content-Type: application/json`)),
  j(base('01.689', 'DEBUG', 'org.apache.http.headers', `${O} << HTTP/1.1 200 OK`)),
  j(base('01.689', 'DEBUG', 'org.apache.http.headers', `${O} << content-type: application/json`)),
  j(base('01.689', 'DEBUG', 'org.apache.http.headers', `${O} << x-request-id: 9b2f6e1c4a8d`)),
  j(base('01.702', 'INFO', 'org.apache.synapse.mediators.builtin.LogMediator', `API_NAME = JAZZCASH_WHATSAPP_VALIDATE_PIN_FLOW, URL = https://xk9p2.api.infobip.com/whatsapp/1/message/template, HTTP_STATUS = 200, RESPONSE_BODY = ${j(infobipResp)}`)),
  j(base('01.705', 'INFO', 'com.jazzcash.waba.FlowController', 'Template message dispatched to provider, continuing flow')),
  `{"@timestamp":"2026-10-14T10:15:01.710Z","level":"INFO","logger":"com.jazzcash.waba.FlowController","message":"Flow state saved: {\\"state\\":\\"AWAIT_PIN\\",\\"msisdn\\":\\"9230012`,
].join('\n');

// ── (c) Plain-text Java stack trace
export const SAMPLE_JAVA = `2026-10-14 10:20:11.402 INFO  [http-nio-8080-exec-3] com.acme.payments.PaymentController - Received payment request orderId=ORD-77812 requestId=req-5f2a9c
2026-10-14 10:20:11.455 WARN  [http-nio-8080-exec-3] com.acme.payments.FraudClient - Fraud service slow: 2400 ms
2026-10-14 10:20:13.871 ERROR [http-nio-8080-exec-3] com.acme.payments.PaymentService - Payment failed for orderId=ORD-77812 requestId=req-5f2a9c
java.lang.IllegalStateException: Could not charge card
	at com.acme.payments.PaymentService.charge(PaymentService.java:142)
	at com.acme.payments.PaymentController.pay(PaymentController.java:58)
	at java.base/jdk.internal.reflect.DirectMethodHandleAccessor.invoke(DirectMethodHandleAccessor.java:103)
Caused by: java.net.SocketTimeoutException: Read timed out
	at java.base/sun.nio.ch.NioSocketImpl.timedRead(NioSocketImpl.java:288)
	at com.acme.payments.GatewayClient.post(GatewayClient.java:77)
	... 2 more
2026-10-14 10:20:13.880 INFO  [http-nio-8080-exec-3] com.acme.payments.PaymentController - Responding 502 to client requestId=req-5f2a9c customer=jane.doe@example.com card=4111 1111 1111 1111
2026-10-14 10:20:14.002 ERROR [http-nio-8080-exec-4] com.acme.payments.PaymentService - Payment failed for orderId=ORD-77813 requestId=req-5f2a9d
10.0.0.5 - - [14/Oct/2026:10:20:14 +0000] "POST /api/pay HTTP/1.1" 502 157 "-" "okhttp/4.12"
some line that matches no known format`;

export const SAMPLES = [
  { id: 'inbound', name: 'WSO2 inbound WhatsApp "hi" (wire, chunked)', text: SAMPLE_INBOUND },
  { id: 'outbound', name: 'Infobip call → 200 but REJECTED (NDJSON)', text: SAMPLE_OUTBOUND },
  { id: 'java', name: 'Java stack trace (plain text)', text: SAMPLE_JAVA },
];
