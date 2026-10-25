import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseStrictJson,
  inboundOnebot,
  buildNormalized,
  peerKeyOf,
  dedupeKeyOf,
  chunkText,
  NormalizeError,
} from '../src/index.mjs';

const OB11_GROUP = {
  post_type: 'message',
  message_type: 'group',
  group_id: 123456,
  user_id: 777,
  message_id: 9001,
  self_id: 333,
  time: 1730000000,
  sender: { user_id: 777, nickname: '大肥鱼粉丝', card: '小明' },
  message: [
    { type: 'text', data: { text: '帮我看看构建有没有报错' } },
    { type: 'at', data: { qq: '333' } },
  ],
};

test('OB11 group frame normalizes to the arch §9.1 sample', () => {
  const { messages } = inboundOnebot(OB11_GROUP, { expectedSelfId: '333', receivedAt: 1730000000000 });
  assert.equal(messages.length, 1);
  const m = messages[0];
  assert.equal(m.v, 1);
  assert.equal(m.id, 'onebot:9001');
  assert.equal(m.channel, 'onebot');
  assert.deepEqual(m.peer, { kind: 'group', chatId: '123456', threadId: undefined });
  assert.equal(m.sender.userId, '777');
  assert.equal(m.atBot, true);
  assert.equal(m.text, '帮我看看构建有没有报错');
  assert.deepEqual(m.riskTags, []);
  assert.equal(m.receivedAt, 1730000000000);
});

test('C-03/A2: display text is dropped during normalization', () => {
  const { messages } = inboundOnebot(OB11_GROUP, {});
  const json = JSON.stringify(messages[0]);
  for (const forbidden of ['nickname', 'card', '大肥鱼粉丝', '小明']) {
    assert.ok(!json.includes(forbidden), `normalized object must not contain ${forbidden}`);
  }
  assert.deepEqual(Object.keys(messages[0].sender), ['userId']);
});

test('private message maps chatId to the sender user id', () => {
  const frame = { ...OB11_GROUP, message_type: 'private', group_id: undefined };
  const { messages } = inboundOnebot(frame, {});
  assert.equal(messages[0].peer.kind, 'dm');
  assert.equal(messages[0].peer.chatId, '777');
  assert.equal(peerKeyOf(messages[0]), 'onebot:dm:777');
});

test('unknown segment type is tagged, never silently dropped', () => {
  const frame = { ...OB11_GROUP, message: [...OB11_GROUP.message, { type: 'xml', data: { data: '<msg>' } }] };
  const { messages } = inboundOnebot(frame, {});
  assert.deepEqual(messages[0].riskTags, ['unknown-segment']);
});

test('post_type outside the closed vocabulary is rejected (C-23)', () => {
  assert.throws(() => inboundOnebot({ post_type: 'evil' }), NormalizeError);
});

test('self_id mismatch fails the frame as unauthenticated', () => {
  assert.throws(
    () => inboundOnebot(OB11_GROUP, { expectedSelfId: '999' }),
    (err) => err.code === 'UNAUTHENTICATED',
  );
});

test('JSON5 syntax is refused (parser differential, C-23)', () => {
  for (const bad of ['{a:1}', '{"a":1,}', "{'a':1}", '// c\n{"a":1}', '{"a":0x10}']) {
    assert.throws(() => parseStrictJson(bad), NormalizeError, `should reject ${bad}`);
  }
});

test('duplicate JSON keys are refused', () => {
  assert.throws(() => parseStrictJson('{"post_type":"message","post_type":"message"}'), (e) => e.code === 'BAD_REQUEST');
});

test('oversize text is tagged and bounded', () => {
  const frame = { ...OB11_GROUP, message: [{ type: 'text', data: { text: 'x'.repeat(9000) } }] };
  const { messages } = inboundOnebot(frame, {});
  assert.ok(messages[0].riskTags.includes('oversize'));
  assert.equal(messages[0].text.length, 8000);
});

test('buildNormalized rejects unknown enums', () => {
  assert.throws(
    () => buildNormalized({ channel: 'wechat', peer: { kind: 'dm', chatId: '1' }, sender: { userId: '1' }, text: '', rawRef: { messageId: '1' } }),
    (e) => e.code === 'BAD_REQUEST',
  );
  assert.throws(
    () => buildNormalized({ channel: 'telegram', peer: { kind: 'room', chatId: '1' }, sender: { userId: '1' }, text: '', rawRef: { messageId: '1' } }),
    (e) => e.code === 'BAD_REQUEST',
  );
});

test('dedupe key is stable and content-free', () => {
  const { messages } = inboundOnebot(OB11_GROUP, {});
  assert.equal(dedupeKeyOf(messages[0]), 'onebot:group:123456#9001');
});

test('chunkText splits without breaking surrogate pairs', () => {
  const text = '😀'.repeat(10) + '中'.repeat(10);
  const chunks = chunkText(text, 5);
  assert.equal(chunks.join(''), text);
  for (const c of chunks) assert.ok(c.length <= 5);
});
