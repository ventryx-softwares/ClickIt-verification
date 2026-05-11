const { Client, GatewayIntentBits, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle, REST, Routes, SlashCommandBuilder, PermissionFlagsBits } = require('discord.js');
const express = require('express');
const { neon } = require('@neondatabase/serverless');
const crypto = require('crypto');

const sql = neon(process.env.DATABASE_URL);

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

let iCloudRelayRanges = [];
let iCloudRangesLastFetched = 0;

function ipToLong(ip) {
  return ip.split('.').reduce((acc, oct) => (acc << 8) + parseInt(oct, 10), 0) >>> 0;
}

function cidrContains(cidr, ip) {
  const [base, bits] = cidr.split('/');
  const mask = bits ? ~((1 << (32 - parseInt(bits))) - 1) >>> 0 : 0xFFFFFFFF;
  return (ipToLong(base) & mask) === (ipToLong(ip) & mask);
}

function isIPv4(ip) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(ip);
}

function isICloudRelayIP(ip) {
  if (!isIPv4(ip)) return false;
  return iCloudRelayRanges.some(cidr => cidrContains(cidr, ip));
}

async function refreshICloudRanges() {
  try {
    const res = await fetchWithTimeout('https://mask-api.icloud.com/egress-ip-ranges.csv', {}, 8000);
    const text = await res.text();
    const ranges = text.split('\n')
      .map(line => line.split(',')[0].trim())
      .filter(r => r && r.includes('/'));
    if (ranges.length > 0) {
      iCloudRelayRanges = ranges;
      iCloudRangesLastFetched = Date.now();
      console.log(`[iCloud] Loaded ${ranges.length} egress IP ranges`);
    }
  } catch (err) {
    console.error('[iCloud] Failed to fetch egress ranges:', err.message);
  }
}

const DATACENTER_HOSTNAME_PATTERNS = [
  /amazon/, /amazonaws/, /aws/, /digitalocean/, /linode/, /hetzner/,
  /vultr/, /ovh/, /cloudflare/, /fastly/, /akamai/, /zscaler/,
  /tor-exit/, /torexit/, /mullvad/, /nordvpn/, /expressvpn/,
  /ipvanish/, /surfshark/, /privateinternetaccess/, /pia\./, /cyberghost/,
  /hidemyass/, /protonvpn/, /windscribe/, /hotspotshield/,
  /hosting/, /host\./, /server/, /vps/, /datacenter/, /data-center/,
];

const PROXY_HEADERS = [
  'via', 'x-forwarded-for', 'forwarded-for', 'x-forwarded',
  'forwarded', 'proxy-connection', 'x-proxy-id', 'mt-proxy-id',
  'x-tinyproxy', 'x-bluecoat-via', 'x-cache', 'x-cache-lookup',
  'x-squid-error', 'proxy-authenticate', 'x-real-ip',
];

async function fetchWithTimeout(url, options = {}, timeoutMs = 5000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    return res;
  } finally {
    clearTimeout(timer);
  }
}

async function checkIPAPI(ip, isRelay) {
  try {
    const res = await fetchWithTimeout(
      `http://ip-api.com/json/${ip}?fields=status,proxy,hosting,vpn,tor,query`
    );
    const data = await res.json();
    if (data.status !== 'success') return null;
    const blockHosting = data.hosting && !isRelay;
    if (data.proxy || data.vpn || data.tor || blockHosting) {
      return {
        blocked: true,
        source: 'ip-api',
        detail: data.tor ? 'Tor exit node' : data.vpn ? 'VPN detected' : data.proxy ? 'Proxy detected' : 'Datacenter/hosting IP',
        logType: data.hosting ? 'datacenter' : data.tor ? 'vpn' : 'proxy',
      };
    }
    return { blocked: false };
  } catch {
    return null;
  }
}

async function checkVpnApi(ip, isRelay) {
  try {
    const res = await fetchWithTimeout(
      `https://vpnapi.io/api/${ip}`
    );
    const data = await res.json();
    if (!data.security) return null;
    const { vpn, proxy, tor, relay } = data.security;
    const blockRelay = relay && !isRelay;
    if (vpn || proxy || tor || blockRelay) {
      return {
        blocked: true,
        source: 'vpnapi',
        detail: tor ? 'Tor exit node' : vpn ? 'VPN detected' : proxy ? 'Proxy detected' : 'Apple/iCloud relay',
        logType: tor || vpn ? 'vpn' : 'proxy',
      };
    }
    return { blocked: false };
  } catch {
    return null;
  }
}

async function checkBlackbox(ip) {
  try {
    const res = await fetchWithTimeout(`https://blackbox.ipinfo.app/lookup/${ip}`);
    const text = await res.text();
    if (text.trim() === 'Y') {
      return {
        blocked: true,
        source: 'blackbox',
        detail: 'VPN or anonymiser detected',
        logType: 'vpn',
      };
    }
    return { blocked: false };
  } catch {
    return null;
  }
}

function checkProxyHeaders(headers) {
  for (const header of PROXY_HEADERS) {
    if (headers[header]) {
      if (header === 'x-forwarded-for') {
        const ips = headers[header].split(',').map(s => s.trim());
        if (ips.length > 1) {
          return {
            blocked: true,
            source: 'headers',
            detail: 'Multiple forwarded IPs indicate proxy chain',
            logType: 'proxy',
          };
        }
        continue;
      }
      if (header === 'x-real-ip' && headers[header] !== headers['x-forwarded-for']) {
        continue;
      }
      return {
        blocked: true,
        source: 'headers',
        detail: `Proxy header detected: ${header}`,
        logType: 'proxy',
      };
    }
  }
  return null;
}

async function checkReverseDNS(ip) {
  try {
    const { Resolver } = require('dns').promises;
    const resolver = new Resolver();
    resolver.setServers(['1.1.1.1', '8.8.8.8']);
    const hostnames = await Promise.race([
      resolver.reverse(ip),
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 3000)),
    ]);
    for (const hostname of hostnames) {
      const lower = hostname.toLowerCase();
      for (const pattern of DATACENTER_HOSTNAME_PATTERNS) {
        if (pattern.test(lower)) {
          return {
            blocked: true,
            source: 'rdns',
            detail: `Datacenter/VPN hostname: ${hostname}`,
            logType: 'datacenter',
          };
        }
      }
    }
    return { blocked: false };
  } catch {
    return { blocked: false };
  }
}

function isAppleUA(headers) {
  const ua = (headers['user-agent'] || '').toLowerCase();
  return (
    (ua.includes('safari') && !ua.includes('chrome') && !ua.includes('android')) ||
    ua.includes('iphone') ||
    ua.includes('ipad') ||
    ua.includes('ipod') ||
    (ua.includes('macintosh') && ua.includes('applewebkit') && !ua.includes('chrome'))
  );
}

async function checkIPThreat(ip, headers) {
  if (Date.now() - iCloudRangesLastFetched > 24 * 60 * 60 * 1000) {
    await refreshICloudRanges();
  }

  const isRelay = isICloudRelayIP(ip);
  const isApple = isAppleUA(headers);
  const skipDatacenterChecks = isRelay || isApple;

  if (isRelay) console.log(`[iCloud] Relay IP: ${ip} — skipping datacenter/rDNS checks`);
  if (isApple && !isRelay) console.log(`[Apple UA] Safari/iOS detected for ${ip} — skipping datacenter/rDNS checks`);

  const headerCheck = skipDatacenterChecks ? null : checkProxyHeaders(headers);
  if (headerCheck) return headerCheck;

  const checks = [
    checkIPAPI(ip, skipDatacenterChecks),
    checkVpnApi(ip, skipDatacenterChecks),
    checkBlackbox(ip),
    skipDatacenterChecks ? Promise.resolve({ blocked: false }) : checkReverseDNS(ip),
  ];

  const [ipApi, vpnApi, blackbox, rdns] = await Promise.all(checks);

  const results = [ipApi, vpnApi, blackbox, rdns].filter(Boolean);
  const blocked = results.find(r => r.blocked);
  if (blocked) return blocked;

  const failedSources = results.length;
  if (failedSources === 0) {
    console.warn(`[SECURITY] All IP check APIs failed for ${ip} — blocking by default (fail-closed)`);
    return {
      blocked: true,
      source: 'failsafe',
      detail: 'Unable to verify your IP — all security checks failed. Try again.',
      logType: 'vpn',
    };
  }

  return { blocked: false };
}

async function saveLog(type, key) {
  await sql`
    insert into logs (type, key, count, updated_at)
    values (${type}, ${key}, 1, now())
    on conflict (type, key)
    do update set count = logs.count + 1, updated_at = now()
  `;
}

async function getLogCount(type, key) {
  const rows = await sql`
    select count from logs where type = ${type} and key = ${key}
  `;
  return rows[0]?.count || 0;
}

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
  await refreshICloudRanges();
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

    const verifiedRows = await sql`select * from verified_ips where user_id = ${target.id}`;
    const verified = verifiedRows[0] || null;

    const [vpnAttempts, proxyAttempts, dcAttempts, altAttempts] = await Promise.all([
      getLogCount('vpn', target.id),
      getLogCount('proxy', target.id),
      getLogCount('datacenter', target.id),
      getLogCount('alts', target.id),
    ]);

    let reply = `**Info for ${target.tag} (${target.id})**\n`;
    if (verified) {
      reply += `**IP:** ${verified.ip}\n`;
      const shared = await sql`select * from verified_ips where ip = ${verified.ip} and user_id != ${target.id}`;
      if (shared.length > 0) {
        reply += `**Shared IPs:** This IP is also used by ${shared.map(s => s.username).join(', ')}\n`;
      }
    } else {
      reply += `**IP:** Not verified yet.\n`;
    }

    reply += `**VPN Attempts:** ${vpnAttempts}\n`;
    reply += `**Proxy Attempts:** ${proxyAttempts}\n`;
    reply += `**Datacenter Attempts:** ${dcAttempts}\n`;
    reply += `**Alt Attempts:** ${altAttempts}\n`;

    return interaction.reply({ content: reply, ephemeral: true });
  }

  if (!interaction.isButton() || interaction.customId !== 'start_verify') return;

  await interaction.deferReply({ ephemeral: true });

  const existingRows = await sql`select user_id from verified_ips where user_id = ${interaction.user.id}`;
  if (existingRows.length > 0) {
    return interaction.editReply({ content: 'You are already verified!' });
  }

  const state = crypto.randomBytes(16).toString('hex');
  await sql`insert into oauth_states (state, user_id, username) values (${state}, ${interaction.user.id}, ${interaction.user.tag})`;

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
    const threatResult = await checkIPThreat(ip, req.headers);
    if (threatResult.blocked) {
      console.warn(`[SECURITY] Blocked ${ip} — reason: ${threatResult.source} / ${threatResult.detail}`);
      saveLog(threatResult.logType, ip);
      return res.status(403).send(renderPage('vpn',
        `Your connection was blocked.<br><strong>Reason:</strong> ${threatResult.detail}<br><br>Disable any VPN, proxy, or anonymiser and try again.`
      ));
    }
  }

  const stateRows = await sql`select * from oauth_states where state = ${state} and used = false`;
  const stateRow = stateRows[0] || null;

  if (!stateRow) {
    return res.status(400).send(renderPage('error', 'Invalid or expired verification link.'));
  }

  await sql`update oauth_states set used = true where state = ${state}`;

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

  const isRelay = isICloudRelayIP(ip);
  const isApple = isAppleUA(req.headers);
  const skipAltIPCheck = isRelay || isApple;

  if (!skipAltIPCheck) {
    const ipRows = await sql`select * from verified_ips where ip = ${ip} and user_id != ${discordUser.id}`;
    if (ipRows.length > 0) {
      console.warn(`Alt detected! IP ${ip} - ${discordUser.username} already used by ${ipRows[0].username}`);
      saveLog('alts', discordUser.id);
      return res.status(403).send(renderPage('banned',
        `This ip is already linked to another account (<strong>${ipRows[0].username}</strong>).<br>Alt accounts are not permitted.`
      ));
    }
  } else {
    console.log(`[Apple/iCloud] Skipping alt-IP check for ${ip} (${discordUser.username}) — relay: ${isRelay}, apple UA: ${isApple}`);
  }

  await sql`
    insert into verified_ips (user_id, username, ip)
    values (${discordUser.id}, ${discordUser.username}, ${ip})
    on conflict (user_id) do update set username = ${discordUser.username}, ip = ${ip}
  `;

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
    success: { title: 'Verified',      color: '#57F287', rgb: '87, 242, 135' },
    error:   { title: 'Error',         color: '#ED4245', rgb: '237, 66, 69' },
    banned:  { title: 'Alt Detected',  color: '#FEE75C', rgb: '254, 231, 92' },
    vpn:     { title: 'Blocked',       color: '#ED4245', rgb: '237, 66, 69' },
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
        inset 0 -1px 0 rgba(255, 255, 255, 0.05);
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
      top: 0; left: 0; right: 0;
      height: 1px;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.5), transparent);
      z-index: 1;
    }
    .card::after {
      content: '';
      position: absolute;
      top: 0; left: 0;
      width: 1px;
      height: 100%;
      background: linear-gradient(180deg, rgba(255,255,255,0.5), transparent, rgba(255,255,255,0.1));
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
    p strong { color: #ededed; font-weight: 600; }
    .badge {
      position: relative;
      z-index: 2;
      margin-top: 36px;
      font-size: 0.7rem;
      color: #525252;
      letter-spacing: 0.06em;
      border-top: 1px solid rgba(255,255,255,0.06);
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
