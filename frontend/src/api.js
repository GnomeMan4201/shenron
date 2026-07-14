export async function getJson(path) {
  const r = await fetch(path);
  if (!r.ok) {
    const text = await r.text();
    throw new Error(`${r.status} ${r.statusText}: ${text}`);
  }
  return r.json();
}

export async function postJson(path, body) {
  const r = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  });
  if (!r.ok) {
    const text = await r.text();
    throw new Error(`${r.status} ${r.statusText}: ${text}`);
  }
  return r.json();
}

export async function streamSse({ url, body, onEvent, signal }) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'text/event-stream' },
    body: JSON.stringify(body || {}),
    signal,
  });
  if (!r.ok || !r.body) {
    const text = await r.text();
    throw new Error(`SSE ${r.status}: ${text}`);
  }
  const reader = r.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const events = buffer.split('\n\n');
    buffer = events.pop() || '';
    for (const raw of events) {
      const ev = parseSse(raw);
      if (ev) onEvent(ev);
    }
  }
}

function parseSse(raw) {
  const lines = raw.split('\n');
  let event = 'message';
  let data = '';
  for (const l of lines) {
    if (l.startsWith('event:')) event = l.slice(6).trim();
    else if (l.startsWith('data:')) data += l.slice(5).trim();
  }
  try { return { event, data: data ? JSON.parse(data) : {} }; }
  catch { return { event, data: { _raw: data } }; }
}
