
import discord
from discord import app_commands
import hashlib
import re
import io
import os
import zipfile

TOKEN = os.environ.get("DISCORD_TOKEN")

ALLOWED = {
    ".lua", ".luac", ".asi", ".dll",
    ".so", ".ini", ".json", ".txt", ".zip"
}

MAX_FILE = 5 * 1024 * 1024
MAX_ZIP_FILES = 50
MAX_ZIP_TOTAL = 10 * 1024 * 1024

PATTERNS = {
    "Keyboard API": [
        r"SetWindowsHookEx",
        r"GetAsyncKeyState",
        r"GetKeyState",
        r"onKeyDown",
        r"onKeyUp",
    ],
    "Network communication": [
        r"performHttpRequest",
        r"socket\.http",
        r"socket\.connect",
        r"discord\.com/api/webhooks",
    ],
    "Dynamic code execution": [
        r"loadstring",
        r"\bdofile\s*\(",
        r"\bload\s*\(",
    ],
    "File access": [
        r"io\.open",
        r"\breadAll\s*\(",
    ],
}

def inspect(name, data):
    ext = os.path.splitext(name)[1].lower()
    digest = hashlib.sha256(data).hexdigest()

    findings = []

    if ext in {".lua", ".txt", ".ini", ".json"}:
        source = data[:MAX_FILE].decode(
            "utf-8", errors="ignore"
        )

        for category, patterns in PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, source, re.I):
                    findings.append(category)
                    break

    elif ext in {".luac", ".asi", ".dll", ".so"}:
        findings.append(
            "Binary file: static source scan unavailable"
        )

    return {
        "name": name,
        "hash": digest,
        "findings": findings
    }

def scan_zip(data):
    results = []
    total_size = 0

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()

            if len(entries) > MAX_ZIP_FILES:
                return [], "ZIP contains too many files."

            for item in entries:
                if item.is_dir():
                    continue

                # Prevent path traversal and encrypted files
                if ".." in item.filename.split("/"):
                    continue

                ext = os.path.splitext(item.filename)[1].lower()

                if ext not in ALLOWED or ext == ".zip":
                    continue

                if item.flag_bits & 1:
                    continue

                if item.file_size > MAX_FILE:
                    continue

                total_size += item.file_size
                if total_size > MAX_ZIP_TOTAL:
                    return [], "ZIP extraction limit exceeded."

                content = archive.read(item)
                results.append(inspect(item.filename, content))

    except (zipfile.BadZipFile, OSError, RuntimeError):
        return [], "Invalid or unreadable ZIP."

    return results, None

class SecurityBot(discord.Client):
    def __init__(self):
        intents = discord.Intents.default()
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self):
        await self.tree.sync()

bot = SecurityBot()

@bot.event
async def on_ready():
    print(f"Bot online: {bot.user}")

@bot.tree.command(
    name="scan",
    description="Scan file MonetLoader GTA SA-MP"
)
@app_commands.describe(file="Upload file Lua, Luac, DLL, ZIP, dll.")
async def scan_command(
    interaction: discord.Interaction,
    file: discord.Attachment
):
    await interaction.response.defer(ephemeral=True)

    name = file.filename
    ext = os.path.splitext(name)[1].lower()

    if ext not in ALLOWED:
        await interaction.followup.send(
            "Format file tidak didukung."
        )
        return

    if file.size > MAX_FILE:
        await interaction.followup.send(
            "File terlalu besar. Maksimal 5 MB."
        )
        return

    try:
        data = await file.read()
    except discord.HTTPException:
        await interaction.followup.send(
            "Gagal membaca file."
        )
        return

    if ext == ".zip":
        results, error = scan_zip(data)

        if error:
            await interaction.followup.send(error)
            return

        if not results:
            await interaction.followup.send(
                "Tidak ada file yang dapat diperiksa di ZIP."
            )
            return
    else:
        results = [inspect(name, data)]

    lines = [
        "🛡️ **MONETLOADER SECURITY SCAN**",
        f"File: `{name}`",
        f"Files checked: **{len(results)}**",
    ]

    for result in results[:15]:
        lines.append(f"\n📄 `{result['name']}`")
        if result["findings"]:
            lines.append(
                "⚠️ Indicators: " +
                ", ".join(result["findings"])
            )
        else:
            lines.append(
                "No configured indicators found."
            )
        lines.append(
            f"SHA256: `{result['hash']}`"
        )

    lines.append(
        "\n⚠️ Indicators are not proof of keylogging. "
        "Binary files need deeper analysis."
    )

    report = "\n".join(lines)

    await interaction.followup.send(
        report[:1900],
        ephemeral=True
    )

if not TOKEN:
    raise RuntimeError("DISCORD_TOKEN belum diatur!")

bot.run(TOKEN)
