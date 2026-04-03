import fs from 'fs';
import path from 'path';
import {
  Client,
  Events,
  GatewayIntentBits,
  Message,
  MessageReaction,
  PartialMessageReaction,
  PartialUser,
  Partials,
  TextChannel,
  User,
} from 'discord.js';

import { ASSISTANT_NAME, TRIGGER_PATTERN } from '../config.js';
import { readEnvFile } from '../env.js';
import { resolveGroupFolderPath } from '../group-folder.js';
import { logger } from '../logger.js';
import { registerChannel, ChannelOpts } from './registry.js';
import {
  Channel,
  OnChatMetadata,
  OnInboundMessage,
  RegisteredGroup,
} from '../types.js';

// IS_VOICE_MESSAGE flag — bit 13 (value 8192).
// Discord sets this on messages that contain a mobile voice note attachment.
// discord.js doesn't expose MessageFlags.IsVoiceMessage in all versions,
// so we check the raw bitfield directly.
const IS_VOICE_MESSAGE_FLAG = 1 << 13; // 8192

export interface DiscordChannelOpts {
  onMessage: OnInboundMessage;
  onChatMetadata: OnChatMetadata;
  registeredGroups: () => Record<string, RegisteredGroup>;
}

export class DiscordChannel implements Channel {
  name = 'discord';

  private client: Client | null = null;
  private opts: DiscordChannelOpts;
  private botToken: string;
  private pendingReactions: Map<string, Message> = new Map();

  constructor(botToken: string, opts: DiscordChannelOpts) {
    this.botToken = botToken;
    this.opts = opts;
  }

  async connect(): Promise<void> {
    this.client = new Client({
      intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
        GatewayIntentBits.DirectMessages,
        GatewayIntentBits.GuildMessageReactions,
      ],
      // Partials are required to receive reaction events on messages that
      // aren't in the cache (e.g. older messages, DM channels).
      partials: [Partials.Message, Partials.Channel, Partials.Reaction],
    });

    this.client.on(Events.MessageCreate, async (message: Message) => {
      // Ignore bot messages (including own)
      if (message.author.bot) return;

      const channelId = message.channelId;
      const chatJid = `dc:${channelId}`;
      let content = message.content;
      const timestamp = message.createdAt.toISOString();
      const senderName =
        message.member?.displayName ||
        message.author.displayName ||
        message.author.username;
      const sender = message.author.id;
      const msgId = message.id;

      // Determine chat name
      let chatName: string;
      if (message.guild) {
        const textChannel = message.channel as TextChannel;
        chatName = `${message.guild.name} #${textChannel.name}`;
      } else {
        chatName = senderName;
      }

      // Translate Discord @bot mentions into TRIGGER_PATTERN format.
      // Discord mentions look like <@botUserId> — these won't match
      // TRIGGER_PATTERN (e.g., ^@Andy\b), so we prepend the trigger
      // when the bot is @mentioned.
      if (this.client?.user) {
        const botId = this.client.user.id;
        const isBotMentioned =
          message.mentions.users.has(botId) ||
          content.includes(`<@${botId}>`) ||
          content.includes(`<@!${botId}>`);

        if (isBotMentioned) {
          // Strip the <@botId> mention to avoid visual clutter
          content = content
            .replace(new RegExp(`<@!?${botId}>`, 'g'), '')
            .trim();
          // Prepend trigger if not already present
          if (!TRIGGER_PATTERN.test(content)) {
            content = `@${ASSISTANT_NAME} ${content}`;
          }
        }
      }

      // Store chat metadata for discovery (runs for all messages, not just registered)
      const isGroup = message.guild !== null;
      this.opts.onChatMetadata(
        chatJid,
        timestamp,
        chatName,
        'discord',
        isGroup,
      );

      // Only process fully for registered groups — look up early so we have
      // the group folder path available for image caching below.
      const group = this.opts.registeredGroups()[chatJid];
      if (!group) {
        logger.debug(
          { chatJid, chatName },
          'Message from unregistered Discord channel',
        );
        return;
      }

      const groupFolderPath = resolveGroupFolderPath(group.folder);

      // Detect voice note: IS_VOICE_MESSAGE flag on the message
      const isVoiceNote =
        ((message.flags?.bitfield ?? 0) & IS_VOICE_MESSAGE_FLAG) !== 0;

      // Handle attachments
      if (message.attachments.size > 0) {
        const attachmentDescriptions = await Promise.all(
          [...message.attachments.values()].map(async (att) => {
            const contentType = att.contentType || '';

            // Voice note — transcribe via Whisper before delivering to agent
            if (isVoiceNote && contentType.startsWith('audio/')) {
              logger.info(
                { msgId, url: att.url },
                'Voice note detected — transcribing',
              );
              const transcript = await transcribeAudio(att.url);
              if (transcript) {
                logger.info(
                  { msgId, length: transcript.length },
                  'Voice note transcribed',
                );
                return `[Voice Note: "${transcript}"]`;
              }
              logger.warn(
                { msgId },
                'Voice note transcription failed — using URL fallback',
              );
              return `[Voice Note (untranscribed): ${att.url}]`;
            }

            // Image — download to group's .image-cache/ folder so the agent
            // can use the Read tool to view it with Claude Vision.
            // Container path: /workspace/group/.image-cache/<msgId>-<filename>
            if (contentType.startsWith('image/')) {
              const containerPath = await downloadImageToCache(
                att.url,
                groupFolderPath,
                msgId,
                att.name || 'image.jpg',
              );
              if (containerPath) {
                logger.info(
                  { msgId, containerPath },
                  'Image cached for agent vision',
                );
                return `[Image: ${att.name || 'image'} | ${containerPath}]`;
              }
              // Download failed — pass URL as hint (agent can't Read it, but has context)
              logger.warn(
                { msgId },
                'Image download failed — passing URL hint',
              );
              return `[Image: ${att.name || 'image'} | url: ${att.url}]`;
            }

            if (contentType.startsWith('video/')) {
              return `[Video: ${att.name || 'video'}]`;
            } else if (contentType.startsWith('audio/')) {
              // Non-voice audio — include URL so agent can reference it
              return `[Audio: ${att.name || 'audio'} | ${att.url}]`;
            } else {
              return `[File: ${att.name || 'file'}]`;
            }
          }),
        );

        if (content) {
          content = `${content}\n${attachmentDescriptions.join('\n')}`;
        } else {
          content = attachmentDescriptions.join('\n');
        }
      }

      // Handle reply context — include who the user is replying to
      if (message.reference?.messageId) {
        try {
          const repliedTo = await message.channel.messages.fetch(
            message.reference.messageId,
          );
          const replyAuthor =
            repliedTo.member?.displayName ||
            repliedTo.author.displayName ||
            repliedTo.author.username;
          content = `[Reply to ${replyAuthor}] ${content}`;
        } catch {
          // Referenced message may have been deleted
        }
      }

      // React immediately to indicate message is being processed
      message.react('⚙️').catch((err: unknown) => {
        logger.debug({ msgId, err }, 'Failed to add processing reaction');
      });
      this.pendingReactions.set(chatJid, message);

      // Deliver message — startMessageLoop() will pick it up
      this.opts.onMessage(chatJid, {
        id: msgId,
        chat_jid: chatJid,
        sender,
        sender_name: senderName,
        content,
        timestamp,
        is_from_me: false,
      });

      logger.info(
        { chatJid, chatName, sender: senderName },
        'Discord message stored',
      );
    });

    // Handle reaction events — lets users react to bot messages as a low-friction
    // alternative to typing a reply. Only fires for reactions on the bot's own messages.
    this.client.on(
      Events.MessageReactionAdd,
      async (
        reaction: MessageReaction | PartialMessageReaction,
        user: User | PartialUser,
      ) => {
        // Ignore bot reactions (our own ⚙️/✅ reactions would re-trigger otherwise)
        if (user.bot) return;
        if (!this.client?.user) return;

        // Resolve partial reaction (uncached — common for older messages)
        let fullReaction = reaction;
        if (reaction.partial) {
          try {
            fullReaction = await reaction.fetch();
          } catch (err) {
            logger.debug({ err }, 'Failed to fetch partial reaction');
            return;
          }
        }

        // Resolve partial message
        const rawMessage = fullReaction.message;
        const botMessage = rawMessage.partial
          ? await rawMessage.fetch().catch(() => null)
          : rawMessage;
        if (!botMessage) return;

        // Only respond to reactions on our own messages
        if (botMessage.author?.id !== this.client.user.id) return;

        const channelId = botMessage.channelId;
        const chatJid = `dc:${channelId}`;

        // Only route for registered groups
        const group = this.opts.registeredGroups()[chatJid];
        if (!group) return;

        // Get the reactor's display name (server nickname if available)
        let senderName: string = user.username ?? user.id;
        if (botMessage.guild) {
          try {
            const member = await botMessage.guild.members.fetch(user.id);
            senderName = member.displayName;
          } catch {
            // Fall back to username if member fetch fails
          }
        }

        // Truncate the original message for context (avoid bloating prompt)
        const originalSnippet = (botMessage.content || '(no text)')
          .replace(/\n+/g, ' ')
          .slice(0, 200);

        const emoji = fullReaction.emoji.name ?? fullReaction.emoji.toString();

        // Format as a routable message with full context for the agent.
        // The agent sees the emoji used and what message it was reacted to,
        // so it can respond appropriately. User can still type a follow-up
        // message for additional context — both paths work independently.
        const content = `@${ASSISTANT_NAME} [Reaction: ${emoji}] to your message: "${originalSnippet}"`;

        const timestamp = new Date().toISOString();

        logger.info(
          { chatJid, emoji, messageId: botMessage.id, sender: senderName },
          'Reaction received on bot message',
        );

        this.opts.onMessage(chatJid, {
          id: `reaction-${botMessage.id}-${user.id}-${Date.now()}`,
          chat_jid: chatJid,
          sender: user.id,
          sender_name: senderName,
          content,
          timestamp,
          is_from_me: false,
        });
      },
    );

    // Handle errors gracefully
    this.client.on(Events.Error, (err) => {
      logger.error({ err: err.message }, 'Discord client error');
    });

    return new Promise<void>((resolve) => {
      this.client!.once(Events.ClientReady, (readyClient) => {
        logger.info(
          { username: readyClient.user.tag, id: readyClient.user.id },
          'Discord bot connected',
        );
        console.log(`\n  Discord bot: ${readyClient.user.tag}`);
        console.log(
          `  Use /chatid command or check channel IDs in Discord settings\n`,
        );
        resolve();
      });

      this.client!.login(this.botToken);
    });
  }

  async sendMessage(jid: string, text: string): Promise<void> {
    if (!this.client) {
      logger.warn('Discord client not initialized');
      return;
    }

    try {
      const channelId = jid.replace(/^dc:/, '');
      const channel = await this.client.channels.fetch(channelId);

      if (!channel || !('send' in channel)) {
        logger.warn({ jid }, 'Discord channel not found or not text-based');
        return;
      }

      const textChannel = channel as TextChannel;

      // Discord has a 2000 character limit per message — split if needed
      const MAX_LENGTH = 2000;
      if (text.length <= MAX_LENGTH) {
        await textChannel.send(text);
      } else {
        for (let i = 0; i < text.length; i += MAX_LENGTH) {
          await textChannel.send(text.slice(i, i + MAX_LENGTH));
        }
      }
      logger.info({ jid, length: text.length }, 'Discord message sent');

      // Swap ⚙️ processing reaction to ✅ now that response is sent
      const pendingMsg = this.pendingReactions.get(jid);
      if (pendingMsg) {
        this.pendingReactions.delete(jid);
        try {
          const gearReaction = pendingMsg.reactions.cache.get('⚙️');
          if (gearReaction)
            await gearReaction.users.remove(this.client!.user!.id);
          await pendingMsg.react('✅');
        } catch (reactionErr) {
          logger.debug({ jid, reactionErr }, 'Failed to update reaction');
        }
      }
    } catch (err) {
      logger.error({ jid, err }, 'Failed to send Discord message');
    }
  }

  isConnected(): boolean {
    return this.client !== null && this.client.isReady();
  }

  ownsJid(jid: string): boolean {
    return jid.startsWith('dc:');
  }

  async disconnect(): Promise<void> {
    if (this.client) {
      this.client.destroy();
      this.client = null;
      logger.info('Discord bot stopped');
    }
  }

  async setTyping(jid: string, isTyping: boolean): Promise<void> {
    if (!this.client || !isTyping) return;
    try {
      const channelId = jid.replace(/^dc:/, '');
      const channel = await this.client.channels.fetch(channelId);
      if (channel && 'sendTyping' in channel) {
        await (channel as TextChannel).sendTyping();
      }
    } catch (err) {
      logger.debug({ jid, err }, 'Failed to send Discord typing indicator');
    }
  }
}

/**
 * Download an image from a Discord CDN URL into the group's .image-cache/ folder.
 * Returns the container-side path (/workspace/group/.image-cache/...) so the agent
 * can use the Read tool to view the image with Claude Vision.
 * Returns null on any failure — caller should fall back gracefully.
 */
async function downloadImageToCache(
  url: string,
  groupFolderPath: string,
  msgId: string,
  filename: string,
): Promise<string | null> {
  try {
    // Sanitize filename to avoid path traversal or shell issues
    const safeName =
      filename.replace(/[^a-zA-Z0-9._-]/g, '_') || `image-${Date.now()}.jpg`;
    const cacheDir = path.join(groupFolderPath, '.image-cache');
    fs.mkdirSync(cacheDir, { recursive: true });

    const destPath = path.join(cacheDir, `${msgId}-${safeName}`);
    const containerPath = `/workspace/group/.image-cache/${msgId}-${safeName}`;

    const res = await fetch(url);
    if (!res.ok) {
      logger.warn(
        { status: res.status, url },
        'Failed to download image attachment',
      );
      return null;
    }

    const buffer = Buffer.from(await res.arrayBuffer());
    fs.writeFileSync(destPath, buffer);

    return containerPath;
  } catch (err) {
    logger.error({ err }, 'Image download error');
    return null;
  }
}

/**
 * Transcribe an audio file URL using the Whisper API.
 * Supports OpenAI and Groq (same API shape, different base URL + key).
 *
 * Config (read from .env at call time):
 *   WHISPER_API_KEY  — required. OpenAI (sk-...) or Groq (gsk_...) key.
 *   WHISPER_BASE_URL — optional. Defaults to OpenAI. Set to
 *                      https://api.groq.com/openai/v1 for Groq.
 *
 * Returns transcription string, or null on any failure. Never throws.
 */
async function transcribeAudio(url: string): Promise<string | null> {
  const envVars = readEnvFile(['WHISPER_API_KEY', 'WHISPER_BASE_URL']);
  const apiKey = process.env.WHISPER_API_KEY || envVars.WHISPER_API_KEY;
  const baseUrl =
    process.env.WHISPER_BASE_URL ||
    envVars.WHISPER_BASE_URL ||
    'https://api.openai.com/v1';

  if (!apiKey) {
    logger.warn('WHISPER_API_KEY not set — voice note transcription disabled');
    return null;
  }

  try {
    // Download audio from Discord CDN (signed URL, must fetch immediately)
    const audioRes = await fetch(url);
    if (!audioRes.ok) {
      logger.warn(
        { status: audioRes.status, url },
        'Failed to download voice note',
      );
      return null;
    }
    const buffer = Buffer.from(await audioRes.arrayBuffer());

    // POST to Whisper as multipart form.
    // Discord voice notes are OGG/Opus — Whisper accepts this natively.
    // Groq uses whisper-large-v3-turbo; OpenAI uses whisper-1.
    const isGroq = baseUrl.includes('groq.com');
    const model = isGroq ? 'whisper-large-v3-turbo' : 'whisper-1';

    const form = new FormData();
    form.append('file', new Blob([buffer], { type: 'audio/ogg' }), 'voice.ogg');
    form.append('model', model);
    form.append('response_format', 'text');

    const res = await fetch(`${baseUrl}/audio/transcriptions`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}` },
      body: form,
    });

    if (!res.ok) {
      const errText = await res.text();
      logger.warn({ status: res.status, error: errText }, 'Whisper API error');
      return null;
    }

    // response_format=text returns a plain string (not JSON)
    const transcript = (await res.text()).trim();
    return transcript || null;
  } catch (err) {
    logger.error({ err }, 'Voice note transcription error');
    return null;
  }
}

registerChannel('discord', (opts: ChannelOpts) => {
  const envVars = readEnvFile(['DISCORD_BOT_TOKEN']);
  const token =
    process.env.DISCORD_BOT_TOKEN || envVars.DISCORD_BOT_TOKEN || '';
  if (!token) {
    logger.warn('Discord: DISCORD_BOT_TOKEN not set');
    return null;
  }
  return new DiscordChannel(token, opts);
});
