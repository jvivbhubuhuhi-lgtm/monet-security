
import discord
import re
import os

from discord.ext import commands

TOKEN = os.getenv("DISCORD_TOKEN")

intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents)

PATTERNS = {
    "Potensi keylogger": r"GetAsyncKeyState|GetKeyState",
    "Discord webhook": r"discord(app)?\.com/api/webhooks",
    "Pengiriman data": r"requests\.post|http\.post|socket\.send",
    "Akses file mencurigakan": r"open\(.+['\"]w",
    "Obfuscation": r"loadstring|base64|decode",
}

@bot.event
async def on_ready():
    print(f"Bot aktif: {bot.user}")

@bot.event
async def on_message(message):
    if message.author.bot:
        return

    if message.attachments:
        for file in message.attachments:
            if not file.filename.endswith(".lua"):
                continue

            if file.size > 1_000_000:
                await message.reply("File terlalu besar (maksimal 1 MB).")
                continue

            content = (await file.read()).decode("utf-8", errors="replace")

            found = [
                name for name, pattern in PATTERNS.items()
                if re.search(pattern, content, re.I)
            ]

            if found:
                result = "\n".join(f"⚠️ {item}" for item in found)
                status = "MENCURIGAKAN"
            else:
                result = "Tidak ditemukan pola yang dikenal."
                status = "BELUM DITEMUKAN INDIKASI"

            await message.reply(
                f"🔎 **MONET SECURITY SCANNER**\n"
                f"📄 File: `{file.filename}`\n"
                f"📊 Status: **{status}**\n\n{result}\n\n"
                "Catatan: Hasil ini bukan jaminan file aman."
            )

    await bot.process_commands(message)

bot.run(TOKEN)
