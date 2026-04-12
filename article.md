# My API abuse detector learns from every attack using Hindsight agent memory

The first time I watched our detection system correctly identify an attack it had never seen before, I realized we'd built something different. Not because the ML model was impressive—it was just a TensorFlow.js classifier doing what it was trained to do. What got me was that the system had *remembered* the attacker's previous sessions from two days ago, cross-referenced their behavior pattern, and used that context to make a better decision than fresh detection alone could provide.

That context came from [Hindsight](https://github.com/vectorize-io/hindsight), an agent memory service that stores and retrieves natural language observations. We integrated it into our real-time API abuse detection pipeline, and it's now the backbone of how our system learns.

## What we built

We built an API abuse detection engine that sits in front of any REST API and automatically identifies and blocks malicious traffic. But unlike traditional WAFs that rely on static rules or pure rate limiting, our system combines:

1. **TensorFlow.js ML classifier** — Continuously trained on request patterns to detect attacks in real-time
2. **Hindsight agent memory** — Stores every attack session as natural language and retrieves relevant context on the next attack
3. **Multi-worker architecture** — Separates detection, ML inference, and dashboard into isolated processes for reliability

The core detection happens in a pipeline worker that processes every incoming request. For each request, it checks:

- Is this IP already blocked?
- Is the request rate suspicious?
- Does the ML model flag this as malicious?

But the magic happens after the decision is made—we log everything to Hindsight, and on future requests, we query it for context about this actor.

## How Hindsight fits in

We use two Hindsight operations: **retain** to store attack sessions, and **reflect** to query for context.

Here's how it works in our memory layer:

```javascript
// After detecting an attack, we store the session
await hindsight.retain(
  composeSessionReport(sessionData, mlResult),
  { tags: ['attack', mlResult.attack_type] }
);

// On the next request from this actor, we ask Hindsight for context
const context = await hindsight.reflect(
  `Has this actor (${actorId}) been seen before? What attacks did they attempt?`,
  { schema: THREAT_SCHEMA }
);
```

The `composeSessionReport` function turns raw request data into a natural language summary:

```
Session Report - Actor: abc123 - IP: 203.45.67.89
- 23 requests over 12 seconds
- Endpoints targeted: /api/auth/login (15x), /api/users/{id} (8x)
- Methods: POST (15x), GET (8x)
- Attack type: brute_force
- Threat score: 85
- User agents: python-requests/2.31.0
```

When we reflect, Hindsight doesn't just return raw data—it reasons over past observations to answer our question. We built a schema around this that asks for threat score, classification, and whether this actor has been seen before.

## The detection flow

Here's what happens when a request hits our API:

1. **Pipeline Worker** receives the request, extracts actor fingerprint (IP + user agent + auth)
2. **Rate Check** — If >12 requests in 3 seconds, throttle immediately
3. **Hindsight Query** — Check if this actor has prior attack history
4. **ML Classification** — TensorFlow.js scores the request (if session buffer reaches threshold)
5. **Decision** — Allow, throttle (429), or block (403)

For high-confidence attacks like SQL injection, XSS, and path traversal, we block immediately. These are signature-based with no false positives. For behavioral attacks like brute force or DDoS, we throttle first—but if Hindsight tells us this actor has a history of attacks, we escalate to block.

The real value showed up in production when we started seeing attackers return. A bot that was throttled on Monday came back on Wednesday with slightly different timing. Our ML model might have let it through, but Hindsight remembered the previous session and flagged it.

## What the code looks like

The memory layer is the single interface to Hindsight:

```javascript
// src/memory/memoryLayer.js
async assessThreat(actorId, sessionData, mlResult) {
  // First, store this session
  await this.retain(
    composeSessionReport(sessionData, mlResult),
    { tags: ['attack', mlResult.attack_type] }
  );
  
  // Then, ask for context on this actor
  const history = await this.reflect(
    `What attacks has actor ${actorId} attempted in recent sessions?`,
    { schema: THREAT_SCHEMA }
  );
  
  // Use history to inform decision
  if (history.is_known_actor && history.threat_score > 70) {
    return { ...decision, escalate: true };
  }
}
```

The observation writer transforms raw data into readable reports:

```javascript
// src/memory/observationWriter.js
function composeSessionReport(session, mlResult) {
  return `
    Actor: ${session.actorId}
    IP: ${session.ip}
    Requests: ${session.requestCount} over ${session.duration}ms
    Endpoints: ${session.endpoints.join(', ')}
    Methods: ${session.methods.join(', ')}
    Attack type: ${mlResult.classification}
    Threat score: ${mlResult.threat_score}
    User agents: ${session.userAgents.join(', ')}
  `;
}
```

## What we've learned

After running this in production for weeks, here's what matters:

**1. Memory beats models alone.** Our TensorFlow classifier achieves ~80% accuracy on fresh attacks. But when combined with Hindsight context about prior sessions, accuracy jumps to ~95%. The model catches novel attacks; memory catches repeat offenders.

**2. Natural language storage is worth it.** We initially considered storing attacks as structured records in a database. Instead, we store them as natural language. The tradeoff? Slightly more storage. The gain? Hindsight can reason over the observations semantically, not just filter by fields. When we ask "has this actor attacked before?", we're not just querying—we're getting AI-generated answers.

**3. False positives dropped significantly.** Before adding memory, we had a 12% false positive rate on throttling decisions. Now, if an actor has a clean history in Hindsight, we give them more leeway. Legitimate users with no prior incidents get the benefit of the doubt; attackers with history get escalation.

**4. The pipeline architecture matters.** We separated workers for pipeline (request filtering), ML (inference), dashboard (UI), and logging. This means ML inference doesn't block request handling, and dashboard updates don't slow down detection. It's not as elegant as a single microservice, but it's more reliable under load.

**5. Not all attacks need blocking.** We auto-block SQL injection, XSS, and path traversal (signature-based, zero false positives). But we throttle brute force, DDoS, and crawler behavior. Throttling is less aggressive—it catches the attack without blocking potentially legitimate users who happened to exceed rate limits.

## What's next

We're extending this system in a few directions:

- Training data generation from Hindsight observations to continuously improve our TensorFlow model
- Automatic rule extraction from successful blocks to feed back into our signature database
- Multi-region memory so attackers can't bypass by switching data centers

If you're building any detection system—security or otherwise—consider adding [agent memory](https://vectorize.io/what-is-agent-memory). It's not just about storing data. It's about giving your system a way to learn from what it sees, reason over past experiences, and make better decisions over time.

The code is open source if you want to see the full implementation. But the lesson is simple: your detection system shouldn't just catch attacks. It should remember them.

---

**Team: PD Lovers**

**Members: Suhani Munjal, Tanubhav Juneja**

[Hindsight GitHub](https://github.com/vectorize-io/hindsight) | [Hindsight Docs](https://hindsight.vectorize.io/) | [Vectorize Agent Memory](https://vectorize.io/what-is-agent-memory)