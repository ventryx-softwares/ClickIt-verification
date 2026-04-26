const { Client, GatewayIntentBits, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle, REST, Routes, SlashCommandBuilder, PermissionFlagsBits } = require('discord.js');
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const logsPath = path.join(__dirname, 'logs.json');
function getLogs() {
  if (!fs.existsSync(logsPath)) return { vpn: {}, alts: {} };
  try { return JSON.parse(fs.readFileSync(logsPath, 'utf8')); } catch { return { vpn: {}, alts: {} }; }
}
function saveLog(type, userId) {
  const logs = getLogs();
  if (!logs[type]) logs[type] = {};
  logs[type][userId] = (logs[type][userId] || 0) + 1;
  fs.writeFileSync(logsPath, JSON.stringify(logs, null, 2));
}

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

async function registerCommands() {
  const commands = [
    new SlashCommandBuilder()
      .setName('getip')
      .setDescription('Get IP and verification info for a user')
      .addUserOption(option => 
        option.setName('target')
          .setDescription('The user to check')
          .setRequired(true))
      .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
  ].map(command => command.toJSON());

  const rest = new REST({ version: '10' }).setToken(BOT_TOKEN);
  try {
    console.log('Refreshing application (/) commands...');
    await rest.put(Routes.applicationGuildCommands(CLIENT_ID, GUILD_ID), { body: commands });
    console.log('Successfully reloaded application (/) commands.');
  } catch (error) {
    console.error('Failed to register commands:', error);
  }
}

client.once('ready', async () => {
  console.log(`Logged in as ${client.user.tag}`);
  await registerCommands();
  await ensureVerificationEmbed();
});

async function ensureVerificationEmbed() {
  const channel = await client.channels.fetch(CHANNEL_ID).catch(() => null);
  if (!channel) return console.error('Channel not found. Check CHANNEL_ID.');

  const messages = await channel.messages.fetch({ limit: 20 });
  const existing = messages.find(m =>
    m.author.id === client.user.id &&
    m.embeds.length > 0 &&
    m.embeds[0].title === 'Verify to Access the Server'
  );

  if (existing) {
    console.log('Verification embed already exists, skipping send.');
    return;
  }

  const embed = new EmbedBuilder()
    .setTitle('Verify to Access the Server')
    .setDescription(
      'To gain access and start your **free trial**, you must verify your account.\n\n' +
      '> Click the button below and log in with Discord to complete verification.\n\n' +
      '**One account per ip address.** Alt accounts and VPNs are automaticaly detected and blocked.'
    )
    .setColor(0x5865F2)
    .setFooter({ text: 'ClickIt Verifcation System - Powered by Ventryx' })
    .setTimestamp();

  const row = new ActionRowBuilder().addComponents(
    new ButtonBuilder()
      .setCustomId('start_verify')
      .setLabel('Verify with Discord')
      .setStyle(ButtonStyle.Primary)
  );

  await channel.send({ embeds: [embed], components: [row] });
  console.log('Verification embed sent.');
}

client.on('interactionCreate', async (interaction) => {
  if (interaction.isChatInputCommand() && interaction.commandName === 'getip') {
    const target = interaction.options.getUser('target');
    
    const { data: verified } = await supabase
      .from('verified_ips')
      .select('*')
      .eq('user_id', target.id)
      .maybeSingle();

    const logs = getLogs();
    const vpnAttempts = logs.vpn[target.id] || 0;
    const altAttempts = logs.alts[target.id] || 0;

    let reply = `**Info for ${target.tag} (${target.id})**\n`;
    if (verified) {
      reply += `**IP:** ${verified.ip}\n`;
      const { data: shared } = await supabase
        .from('verified_ips')
        .select('*')
        .eq('ip', verified.ip)
        .neq('user_id', target.id);
      
      if (shared && shared.length > 0) {
        reply += `**Shared IPs:** This IP is also used by ${shared.map(s => s.username).join(', ')}\n`;
      }
    } else {
      reply += `**IP:** Not verified yet.\n`;
    }

    reply += `**VPN Attempts:** ${vpnAttempts}\n`;
    reply += `**Alt Attempts:** ${altAttempts}\n`;

    return interaction.reply({ content: reply, ephemeral: true });
  }

  if (!interaction.isButton() || interaction.customId !== 'start_verify') return;

  await interaction.deferReply({ ephemeral: true });

  const { data: existing } = await supabase
    .from('verified_ips')
    .select('user_id')
    .eq('user_id', interaction.user.id)
    .maybeSingle();

  if (existing) {
    return interaction.editReply({ content: 'You are already verified!' });
  }

  const state = crypto.randomBytes(16).toString('hex');
  await supabase.from('oauth_states').insert({
    state,
    user_id: interaction.user.id,
    username: interaction.user.tag,
  });

  const oauthUrl = `https://discord.com/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=identify&state=${state}`;

  await interaction.editReply({
    content: `**Click below to verify your account via Discord Login:**\n${oauthUrl}\n\n*This link is tied to your account and expires in 10 minutes.*`,
  });
});

const app = express();
app.set('trust proxy', true);

app.get('/callback', async (req, res) => {
  const { code, state } = req.query;
  const ip = req.ip || req.connection.remoteAddress;

  if (!code || !state) {
    return res.status(400).send(renderPage('error', 'Missing OAuth parameters.'));
  }

  if (ip && ip !== '::1' && ip !== '127.0.0.1') {
    try {
      const vpnRes = await fetch(`https://blackbox.ipinfo.app/lookup/${ip}`);
      const isVpn = await vpnRes.text();
      if (isVpn.trim() === 'Y') {
        console.warn(`VPN detected for IP ${ip}`);
        return res.status(403).send(renderPage('vpn',
          `You are using a VPN or Proxy (<strong>${ip}</strong>).<br>Please disable it and try again.`
        ));
      }
    } catch (err) {
      console.error('Failed to check VPN status:', err.message);
    }
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
      `You must log in as <strong>${stateRow.username}</strong> - the account that clicked Verify.`
    ));
  }

  const { data: ipRows } = await supabase
    .from('verified_ips')
    .select('*')
    .eq('ip', ip)
    .neq('user_id', discordUser.id);

  if (ipRows && ipRows.length > 0) {
    console.warn(`Alt detected! IP ${ip} - ${discordUser.username} already used by ${ipRows[0].username}`);
    saveLog('alts', discordUser.id);
    return res.status(403).send(renderPage('banned',
      `This ip is already linked to another account (<strong>${ipRows[0].username}</strong>).<br>Alt accounts are not permitted.`
    ));
  }

  await supabase.from('verified_ips').upsert({
    ip,
    user_id: discordUser.id,
    username: discordUser.username,
  });

  console.log(`Verified: ${discordUser.username} (${discordUser.id}) from IP ${ip}`);

  try {
    const guild = await client.guilds.fetch(GUILD_ID);
    const member = await guild.members.fetch(discordUser.id);

    await member.roles.add(VERIFIED_ROLE);
    console.log(`Verified role granted to ${discordUser.username}`);

    if (member.roles.cache.has(UNVERIFIED_ROLE)) {
      await member.roles.remove(UNVERIFIED_ROLE);
      console.log(`Unverified role removed from ${discordUser.username}`);
    }
  } catch (err) {
    console.error('Failed to update roles:', err.message);
  }

  res.send(renderPage('success', `You're verified, <strong>${discordUser.username}</strong>! Head back to the server.`));
});

app.get('/', (_, res) => res.send('ClickIt Verification Bot is running.'));

app.listen(PORT, () => console.log(`Web server on port ${PORT}`));

client.login(BOT_TOKEN);

function renderPage(type, message) {
  const configs = {
    success: { title: 'Verified',    color: '#57F287', rgb: '87, 242, 135' },
    error:   { title: 'Error',         color: '#ED4245', rgb: '237, 66, 69' },
    banned:  { title: 'Alt Detected', color: '#FEE75C', rgb: '254, 231, 92' },
    vpn:     { title: 'VPN Detected', color: '#ED4245', rgb: '237, 66, 69' },
  };
  const c = configs[type] || configs.error;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${c.title} - ClickIt Verification</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Geist+Mono:wght@400;600&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background-color: #0a0a0a;
      font-family: 'Geist Mono', monospace;
      color: #ededed;
    }
    .card {
      background: rgba(255, 255, 255, 0.06);
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
      border-radius: 20px;
      border: 1px solid rgba(255, 255, 255, 0.15);
      box-shadow: 
        0 8px 32px rgba(0, 0, 0, 0.4),
        inset 0 1px 0 rgba(255, 255, 255, 0.15),
        inset 0 -1px 0 rgba(255, 255, 255, 0.05),
        inset 0 0 0px 0px rgba(255, 255, 255, 0);
      position: relative;
      overflow: hidden;
      padding: 48px 40px;
      max-width: 480px;
      width: 90%;
      text-align: left;
      animation: slideUpFade 0.6s cubic-bezier(0.16, 1, 0.3, 1) forwards;
      opacity: 0;
    }
    .card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 1px;
      background: linear-gradient(
        90deg,
        transparent,
        rgba(255, 255, 255, 0.5),
        transparent
      );
      z-index: 1;
    }
    .card::after {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      width: 1px;
      height: 100%;
      background: linear-gradient(
        180deg,
        rgba(255, 255, 255, 0.5),
        transparent,
        rgba(255, 255, 255, 0.1)
      );
      z-index: 1;
    }
    .status-tint {
      position: absolute;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(${c.rgb}, 0.04);
      pointer-events: none;
      z-index: 0;
    }
    @keyframes slideUpFade {
      0% { opacity: 0; transform: translateY(24px); }
      100% { opacity: 1; transform: translateY(0); }
    }
    h1 {
      position: relative;
      z-index: 2;
      font-size: 1.75rem;
      font-weight: 600;
      color: ${c.color};
      margin-bottom: 16px;
      letter-spacing: -0.02em;
    }
    p {
      position: relative;
      z-index: 2;
      color: #a3a3a3;
      line-height: 1.6;
      font-size: 0.95rem;
      font-weight: 400;
    }
    p strong {
      color: #ededed;
      font-weight: 600;
    }
    .badge {
      position: relative;
      z-index: 2;
      margin-top: 36px;
      font-size: 0.7rem;
      color: #525252;
      letter-spacing: 0.06em;
      border-top: 1px solid rgba(255, 255, 255, 0.06);
      padding-top: 20px;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="status-tint"></div>
    <h1>${c.title}</h1>
    <p>${message}</p>
    <div class="badge">ClickIt Verifcation system - Ventryx</div>
  </div>
</body>
</html>`;
}
