const { Client, GatewayIntentBits, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle } = require('discord.js');
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

// ── CONFIG ──────────────────────────────────────────────────────────────────
const BOT_TOKEN        = process.env.BOT_TOKEN;
const CHANNEL_ID       = '1234567890123456789'; // ← your channel ID here
const VERIFIED_ROLE    = process.env.VERIFIED_ROLE_ID;
const GUILD_ID         = process.env.GUILD_ID;
const RENDER_URL       = process.env.RENDER_URL;
const CLIENT_ID        = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET    = process.env.DISCORD_CLIENT_SECRET;
const PORT             = process.env.PORT || 3000;
const REDIRECT_URI     = 'https://clickit-ver.ventryx.xyz/callback'; // ← hard-coded to avoid encoding issues
// ────────────────────────────────────────────────────────────────────────────

// ── SUPABASE ──────────────────────────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);
// ────────────────────────────────────────────────────────────────────────────

// ── DISCORD BOT ───────────────────────────────────────────────────────────────
const client = new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers]
});

client.once('ready', async () => {
  console.log(`✅ Logged in as ${client.user.tag}`);
  await ensureVerificationEmbed();
});

async function ensureVerificationEmbed() {
  const channel = await client.channels.fetch(CHANNEL_ID).catch(() => null);
  if (!channel) return console.error('❌ Channel not found. Check CHANNEL_ID.');

  const messages = await channel.messages.fetch({ limit: 20 });
  const existing = messages.find(m =>
    m.author.id === client.user.id &&
    m.embeds.length > 0 &&
    m.embeds[0].title === '🔒 Verify to Access the Server'
  );

  if (existing) {
    console.log('📨 Verification embed already exists, skipping send.');
    return;
  }

  const embed = new EmbedBuilder()
    .setTitle('🔒 Verify to Access the Server')
    .setDescription(
      'To gain access and start your **free trial**, you must verify your account.\n\n' +
      '> Click the button below and log in with Discord to complete verification.\n\n' +
      '⚠️ **One account per IP address.** Alt accounts are automatically detected and banned.'
    )
    .setColor(0x5865F2)
    .setFooter({ text: 'ClickIt Verification System • Powered by Ventryx' })
    .setTimestamp();

  const row = new ActionRowBuilder().addComponents(
    new ButtonBuilder()
      .setCustomId('start_verify')
      .setLabel('🔐  Verify with Discord')
      .setStyle(ButtonStyle.Primary)
  );

  await channel.send({ embeds: [embed], components: [row] });
  console.log('📨 Verification embed sent.');
}

client.on('interactionCreate', async (interaction) => {
  if (!interaction.isButton() || interaction.customId !== 'start_verify') return;

  await interaction.deferReply({ ephemeral: true });

  const { data: existing } = await supabase
    .from('verified_ips')
    .select('user_id')
    .eq('user_id', interaction.user.id)
    .maybeSingle();

  if (existing) {
    return interaction.editReply({ content: '✅ You are already verified!' });
  }

  const state = crypto.randomBytes(16).toString('hex');
  await supabase.from('oauth_states').insert({
    state,
    user_id: interaction.user.id,
    username: interaction.user.tag,
  });

  // Build OAuth URL — redirect_uri must NOT go through URLSearchParams to avoid double-encoding
  const oauthUrl = `https://discord.com/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=identify&state=${state}`;

  await interaction.editReply({
    content: `**Click below to verify your account via Discord Login:**\n${oauthUrl}\n\n*This link is tied to your account and expires in 10 minutes.*`,
  });
});
// ────────────────────────────────────────────────────────────────────────────

// ── EXPRESS / OAUTH2 ──────────────────────────────────────────────────────────
const app = express();
app.set('trust proxy', true);

app.get('/callback', async (req, res) => {
  const { code, state } = req.query;
  const ip = req.ip || req.connection.remoteAddress;

  if (!code || !state) {
    return res.status(400).send(renderPage('error', 'Missing OAuth parameters.'));
  }

  const { data: stateRow } = await supabase
    .from('oauth_states')
    .select('*')
    .eq('state', state)
    .eq('used', false)
    .maybeSingle();

  if (!stateRow) {
    return res.status(400).send(renderPage('error', 'Invalid or expired verification link.'));
  }

  await supabase.from('oauth_states').update({ used: true }).eq('state', state);

  let discordUser;
  try {
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
      }),
    });
    const tokenData = await tokenRes.json();

    if (!tokenData.access_token) throw new Error('No access token returned');

    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    discordUser = await userRes.json();
  } catch (err) {
    console.error('OAuth error:', err.message);
    return res.status(500).send(renderPage('error', 'Failed to authenticate with Discord. Please try again.'));
  }

  if (discordUser.id !== stateRow.user_id) {
    return res.status(403).send(renderPage('error',
      `You must log in as <strong>${stateRow.username}</strong> — the account that clicked Verify.`
    ));
  }

  const { data: ipRows } = await supabase
    .from('verified_ips')
    .select('*')
    .eq('ip', ip)
    .neq('user_id', discordUser.id);

  if (ipRows && ipRows.length > 0) {
    console.warn(`🚨 Alt detected! IP ${ip} → ${discordUser.username} already used by ${ipRows[0].username}`);
    return res.status(403).send(renderPage('banned',
      `This IP is already linked to another account (<strong>${ipRows[0].username}</strong>).<br>Alt accounts are not permitted.`
    ));
  }

  await supabase.from('verified_ips').upsert({
    ip,
    user_id: discordUser.id,
    username: discordUser.username,
  });

  console.log(`✅ Verified: ${discordUser.username} (${discordUser.id}) from IP ${ip}`);

  try {
    const guild = await client.guilds.fetch(GUILD_ID);
    const member = await guild.members.fetch(discordUser.id);
    await member.roles.add(VERIFIED_ROLE);
    console.log(`🎭 Role granted to ${discordUser.username}`);
  } catch (err) {
    console.error('⚠️ Failed to grant role:', err.message);
  }

  res.send(renderPage('success', `You're verified, <strong>${discordUser.username}</strong>! Head back to the server.`));
});

app.get('/', (_, res) => res.send('ClickIt Verification Bot is running.'));

app.listen(PORT, () => console.log(`🌐 Web server on port ${PORT}`));
// ────────────────────────────────────────────────────────────────────────────

client.login(BOT_TOKEN);

// ── PAGE RENDERER ─────────────────────────────────────────────────────────────
function renderPage(type, message) {
  const configs = {
    success: { icon: '✅', title: 'Verified!',    color: '#57F287' },
    error:   { icon: '❌', title: 'Error',         color: '#ED4245' },
    banned:  { icon: '🚨', title: 'Alt Detected', color: '#FEE75C' },
  };
  const c = configs[type] || configs.error;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${c.title} — ClickIt Verification</title>
  <link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Inter:wght@400;600&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #0d1117;
      font-family: 'Inter', sans-serif;
      color: #e6edf3;
    }
    .card {
      background: #161b22;
      border: 1px solid #30363d;
      border-top: 3px solid ${c.color};
      border-radius: 12px;
      padding: 48px 40px;
      max-width: 460px;
      width: 90%;
      text-align: center;
      box-shadow: 0 8px 32px rgba(0,0,0,0.4);
      animation: fadeUp 0.4s ease;
    }
    @keyframes fadeUp {
      from { opacity: 0; transform: translateY(20px); }
      to   { opacity: 1; transform: translateY(0); }
    }
    .icon { font-size: 3rem; margin-bottom: 16px; }
    h1 { font-family: 'Space Mono', monospace; font-size: 1.5rem; color: ${c.color}; margin-bottom: 12px; }
    p { color: #8b949e; line-height: 1.6; }
    p strong { color: #e6edf3; }
    .badge { margin-top: 28px; font-family: 'Space Mono', monospace; font-size: 0.65rem; color: #484f58; letter-spacing: 0.08em; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">${c.icon}</div>
    <h1>${c.title}</h1>
    <p>${message}</p>
    <div class="badge">CLICKIT VERIFICATION SYSTEM • VENTRYX</div>
  </div>
</body>
</html>`;
}
