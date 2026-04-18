const { Client, GatewayIntentBits, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle } = require('discord.js');
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

// ── CONFIG ──────────────────────────────────────────────────────────────────
const BOT_TOKEN      = process.env.BOT_TOKEN;
const CHANNEL_ID     = '1234567890123456789'; // ← hard-code your channel ID here
const VERIFIED_ROLE  = process.env.VERIFIED_ROLE_ID;
const GUILD_ID       = process.env.GUILD_ID;
const RENDER_URL     = process.env.RENDER_URL;
const PORT           = process.env.PORT || 3000;
// ────────────────────────────────────────────────────────────────────────────

// ── SUPABASE ──────────────────────────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY // service role key — bypasses RLS
);
// ────────────────────────────────────────────────────────────────────────────

// ── DISCORD CLIENT ────────────────────────────────────────────────────────────
const client = new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers]
});

client.once('ready', async () => {
  console.log(`✅ Logged in as ${client.user.tag}`);
  await sendVerificationEmbed();
});

async function sendVerificationEmbed() {
  const channel = await client.channels.fetch(CHANNEL_ID).catch(() => null);
  if (!channel) return console.error('❌ Channel not found. Check CHANNEL_ID.');

  const embed = new EmbedBuilder()
    .setTitle('🔒 Verify to Access the Server')
    .setDescription(
      'To gain access and start your **free trial**, you must verify your account.\n\n' +
      '> Click the button below to complete verification.\n\n' +
      '⚠️ **One account per IP address.** Alt accounts are automatically detected and banned.'
    )
    .setColor(0x5865F2)
    .setFooter({ text: 'ClickIt Verification System • Powered by Ventryx' })
    .setTimestamp();

  const row = new ActionRowBuilder().addComponents(
    new ButtonBuilder()
      .setCustomId('start_verify')
      .setLabel('✅  Verify Now')
      .setStyle(ButtonStyle.Primary)
  );

  await channel.send({ embeds: [embed], components: [row] });
  console.log('📨 Verification embed sent.');
}

client.on('interactionCreate', async (interaction) => {
  if (!interaction.isButton() || interaction.customId !== 'start_verify') return;

  await interaction.deferReply({ ephemeral: true });

  // Check if already verified
  const { data: existing } = await supabase
    .from('verified_ips')
    .select('user_id')
    .eq('user_id', interaction.user.id)
    .maybeSingle();

  if (existing) {
    return interaction.editReply({ content: '✅ You are already verified!' });
  }

  // Generate one-time token
  const token = crypto.randomBytes(24).toString('hex');
  await supabase.from('tokens').insert({
    token,
    user_id: interaction.user.id,
    username: interaction.user.tag,
  });

  const verifyUrl = `${RENDER_URL}/verify?token=${token}`;

  await interaction.editReply({
    content: `**Click the link below to verify your account:**\n${verifyUrl}\n\n*This link is single-use and tied to your account.*`,
  });
});
// ────────────────────────────────────────────────────────────────────────────

// ── EXPRESS SERVER ────────────────────────────────────────────────────────────
const app = express();
app.set('trust proxy', true);

app.get('/verify', async (req, res) => {
  const { token } = req.query;
  const ip = req.ip || req.connection.remoteAddress;

  if (!token) {
    return res.status(400).send(renderPage('error', 'Missing verification token.'));
  }

  // Validate token
  const { data: tokenRow } = await supabase
    .from('tokens')
    .select('*')
    .eq('token', token)
    .eq('used', false)
    .maybeSingle();

  if (!tokenRow) {
    return res.status(400).send(renderPage('error', 'Invalid or already used token.'));
  }

  // Alt check — same IP, different user?
  const { data: ipRows } = await supabase
    .from('verified_ips')
    .select('*')
    .eq('ip', ip)
    .neq('user_id', tokenRow.user_id);

  if (ipRows && ipRows.length > 0) {
    console.warn(`🚨 Alt detected! IP ${ip} → tried as ${tokenRow.user_id}, already used by ${ipRows[0].user_id}`);
    return res.status(403).send(renderPage('banned',
      `This IP address is already linked to another account (<strong>${ipRows[0].username}</strong>).<br>Alt accounts are not permitted.`
    ));
  }

  // Mark token used
  await supabase.from('tokens').update({ used: true }).eq('token', token);

  // Log IP
  await supabase.from('verified_ips').upsert({
    ip,
    user_id: tokenRow.user_id,
    username: tokenRow.username,
  });

  console.log(`✅ Verified: ${tokenRow.username} (${tokenRow.user_id}) from IP ${ip}`);

  // Grant role
  try {
    const guild = await client.guilds.fetch(GUILD_ID);
    const member = await guild.members.fetch(tokenRow.user_id);
    await member.roles.add(VERIFIED_ROLE);
    console.log(`🎭 Role granted to ${tokenRow.username}`);
  } catch (err) {
    console.error('⚠️ Failed to grant role:', err.message);
  }

  res.send(renderPage('success', `You're verified, <strong>${tokenRow.username}</strong>! Head back to the server.`));
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
