const { Client, GatewayIntentBits, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle } = require('discord.js');
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

const BOT_TOKEN        = process.env.BOT_TOKEN;
const CHANNEL_ID       = '1495042210427830426';
const VERIFIED_ROLE    = process.env.VERIFIED_ROLE_ID;
const UNVERIFIED_ROLE  = '1495086433583501353';
const GUILD_ID         = process.env.GUILD_ID;
const RENDER_URL       = process.env.RENDER_URL;
const CLIENT_ID        = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET    = process.env.DISCORD_CLIENT_SECRET;
const PORT             = process.env.PORT || 3000;
const REDIRECT_URI     = 'https://clickit-ver.ventryx.xyz/callback';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

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
    m.embeds[0].title === 'Verify'
  );

  if (existing) {
    console.log('Verification embed already exists, skipping send.');
    return;
  }

  const embed = new EmbedBuilder()
    .setTitle('verify')
    .setDescription(
      'To gain accses please verify yourself to the father.\n\n' +
      '> Click the button below and log into discord using oAuth.\n\n' +
      '**One person per IP address.** alt accounts shall be removed of..'
    )
    .setColor(0xFFD700)
    .setFooter({ text: 'Click it - here to help you ig' })
    .setTimestamp();

  const row = new ActionRowBuilder().addComponents(
    new ButtonBuilder()
      .setCustomId('start_verify')
      .setLabel('Submit to Judgment')
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
    return interaction.editReply({ content: 'Your soul has already been deemed and found worthy.' });
  }

  const state = crypto.randomBytes(16).toString('hex');
  await supabase.from('oauth_states').insert({
    state,
    user_id: interaction.user.id,
    username: interaction.user.tag,
  });

  const oauthUrl = `https://discord.com/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=identify&state=${state}`;

  await interaction.editReply({
    content: `**Click below to submit yourself to judgement day:**\n${oauthUrl}\n\n. This link expires in 10 minutes.*`,
  });
});

const app = express();
app.set('trust proxy', true);

app.get('/callback', async (req, res) => {
  const { code, state } = req.query;
  const ip = req.ip || req.connection.remoteAddress;

  if (!code || !state) {
    return res.status(400).send(renderPage('error', 'The Council finds your request... lacking, try again.'));
  }

  const { data: stateRow } = await supabase
    .from('oauth_states')
    .select('*')
    .eq('state', state)
    .eq('used', false)
    .maybeSingle();

  if (!stateRow) {
    return res.status(400).send(renderPage('error', 'Your token of passage is invalid or expired, Machine.'));
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
    return res.status(500).send(renderPage('error', 'The light of Discord has failed us. Try again.'));
  }

  if (discordUser.id !== stateRow.user_id) {
    return res.status(403).send(renderPage('error',
      `You must present the soul of <strong>${stateRow.username}</strong> - the one who sought passage.`
    ));
  }

  const { data: ipRows } = await supabase
    .from('verified_ips')
    .select('*')
    .eq('ip', ip)
    .neq('user_id', discordUser.id);

  if (ipRows && ipRows.length > 0) {
    console.warn(`🚨 Alt detected! IP ${ip} - ${discordUser.username} already used by ${ipRows[0].username}`);
    return res.status(403).send(renderPage('banned',
      `This IP is already in use by (<strong>${ipRows[0].username}</strong>).<br>thee shall perish!`
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
    console.log(`Verified role granted to ${discordUser.username}`);

    if (member.roles.cache.has(UNVERIFIED_ROLE)) {
      await member.roles.remove(UNVERIFIED_ROLE);
      console.log(`🗑️ Unverified role removed from ${discordUser.username}`);
    }
  } catch (err) {
    console.error('Failed to update roles:', err.message);
  }

  res.send(renderPage('success', `Your soul is verified, <strong>${discordUser.username}</strong>! You may enter the layers of this server.`));
});

app.get('/', (_, res) => res.send('The Righteous Hand of the Father is watching.'));

app.listen(PORT, () => console.log(`Web server on port ${PORT}`));

client.login(BOT_TOKEN);

function renderPage(type, message) {
  const configs = {
    success: { icon: '✨', title: 'machine, you proved yourself worthy.',    color: '#FFD700', bgGlow: 'rgba(255, 215, 0, 0.15)' },
    error:   { icon: '😔', title: 'uhm... yeah try again!',     color: '#ED4245', bgGlow: 'rgba(237, 66, 69, 0.15)' },
    banned:  { icon: '🩸', title: 'MACHINE, YOU INSIGNIFICANT FUCK!',   color: '#8A0303', bgGlow: 'rgba(138, 3, 3, 0.15)' },
  };
  const c = configs[type] || configs.error;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${c.title} - Holy Verification</title>
  <link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@700&family=Rajdhani:wght@500;700&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background-color: #020202;
      background-image: 
        radial-gradient(circle at 50% 0%, ${c.bgGlow} 0%, transparent 60%),
        linear-gradient(to bottom, #020202 0%, #080808 100%);
      font-family: 'Rajdhani', sans-serif;
      color: #e6edf3;
      overflow: hidden;
      position: relative;
    }
    body::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0; bottom: 0;
      background: repeating-linear-gradient(
        0deg,
        rgba(0, 0, 0, 0.15),
        rgba(0, 0, 0, 0.15) 1px,
        transparent 1px,
        transparent 2px
      );
      pointer-events: none;
      z-index: 1;
    }
    .cross {
      position: absolute;
      color: rgba(255, 255, 255, 0.02);
      font-size: 35rem;
      font-family: 'Cinzel', serif;
      z-index: 0;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      pointer-events: none;
      user-select: none;
    }
    .card {
      position: relative;
      background: rgba(12, 12, 14, 0.85);
      border: 1px solid rgba(255, 255, 255, 0.05);
      padding: 60px 50px;
      max-width: 500px;
      width: 90%;
      text-align: center;
      z-index: 2;
      box-shadow: 0 0 40px rgba(0, 0, 0, 0.9), inset 0 0 30px rgba(0, 0, 0, 0.6);
      backdrop-filter: blur(8px);
      clip-path: polygon(
        0 20px, 20px 0, 
        calc(100% - 20px) 0, 100% 20px, 
        100% calc(100% - 20px), calc(100% - 20px) 100%, 
        20px 100%, 0 calc(100% - 20px)
      );
      animation: descend 0.8s cubic-bezier(0.16, 1, 0.3, 1) forwards;
    }
    .card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0; height: 3px;
      background: ${c.color};
      box-shadow: 0 0 20px ${c.color}, 0 0 10px ${c.color};
    }
    .card::after {
      content: '';
      position: absolute;
      bottom: 0; left: 0; right: 0; height: 1px;
      background: linear-gradient(90deg, transparent, ${c.color}, transparent);
      opacity: 0.3;
    }
    @keyframes descend {
      0% { opacity: 0; transform: translateY(-30px) scale(0.95); filter: brightness(1.5); }
      100% { opacity: 1; transform: translateY(0) scale(1); filter: brightness(1); }
    }
    .icon-container {
      position: relative;
      display: inline-block;
      margin-bottom: 24px;
    }
    .icon { 
      font-size: 4.5rem; 
      line-height: 1;
      position: relative;
      z-index: 2;
      filter: drop-shadow(0 0 20px ${c.color});
      animation: pulse-icon 2s infinite alternate;
    }
    @keyframes pulse-icon {
      0% { transform: scale(1); filter: drop-shadow(0 0 15px ${c.color}); }
      100% { transform: scale(1.08); filter: drop-shadow(0 0 30px ${c.color}); }
    }
    h1 { 
      font-family: 'Cinzel', serif; 
      font-size: 2.8rem; 
      color: ${c.color}; 
      margin-bottom: 20px; 
      text-transform: uppercase; 
      letter-spacing: 6px; 
      text-shadow: 0 0 15px ${c.color}, 0 4px 15px rgba(0,0,0,0.9);
      line-height: 1.1;
    }
    p { 
      color: #b0b8c2; 
      line-height: 1.6; 
      font-size: 1.25rem; 
      text-transform: uppercase;
      letter-spacing: 2px;
    }
    p strong { 
      color: #fff; 
      font-weight: 700;
      text-shadow: 0 0 10px rgba(255,255,255,0.4); 
    }
    .badge { 
      margin-top: 45px; 
      font-family: 'Rajdhani', sans-serif; 
      font-size: 0.85rem; 
      font-weight: 700;
      color: #666; 
      letter-spacing: 5px; 
      text-transform: uppercase; 
      border-top: 1px solid rgba(255, 255, 255, 0.05);
      padding-top: 25px;
    }
  </style>
</head>
<body>
  <div class="cross">†</div>
  <div class="card">
    <div class="icon-container">
      <div class="icon">${c.icon}</div>
    </div>
    <h1>${c.title}</h1>
    <p>${message}</p>
    <div class="badge">the rightous hand of the father - gabriel</div>
  </div>
</body>
</html>`;
}
