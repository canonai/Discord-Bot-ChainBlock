import os
import re
import discord
import requests
from discord.ext import commands

# Ganti 'YOUR_DISCORD_BOT_TOKEN' dengan token bot Discord Anda
DISCORD_TOKEN = "Token"

# Ganti 'YOUR_VIRUSTOTAL_API_KEY' dengan API key VirusTotal Anda
VT_API_KEY = "VT"

intents = discord.Intents.default()
intents.messages = True
intents.message_content = True  # Pastikan message_content intent diaktifkan di Discord Dev Portal
bot = commands.Bot(command_prefix="!", intents=intents)

# Regex sederhana untuk mendeteksi URL dalam pesan
URL_REGEX = r'https?://[^\s]+'


@bot.event
async def on_ready():
  print(f"Bot telah masuk sebagai {bot.user}")


@bot.event
async def on_message(message):
  # Hindari merespon pesan dari bot sendiri
  if message.author == bot.user:
    return

  # Cari URL dalam pesan
  urls = re.findall(URL_REGEX, message.content)
  if urls:
    for url in urls:
      report = analyze_url(url)
      if report is not None:
        # Parsing hasil
        detection_summary = process_virustotal_report(report)
        await message.channel.send(embed=detection_summary)
      else:
        await message.channel.send("Gagal menganalisis URL tersebut.")

  # Pastikan event on_message tidak memblok command commands lainnya
  await bot.process_commands(message)


def analyze_url(url):
  """Mengirim URL ke VirusTotal untuk dianalisis dan mengembalikan laporan."""
  vt_url = "https://www.virustotal.com/api/v3/urls"
  headers = {"x-apikey": VT_API_KEY}

  # Encode URL
  data = {"url": url}
  response = requests.post(vt_url, headers=headers, data=data)

  if response.status_code == 200:
    # Ambil ID analisis
    analysis_id = response.json().get("data", {}).get("id")
    if analysis_id:
      return get_report(analysis_id)

  print("Error saat mengirim URL ke VirusTotal:", response.text)
  return None


def get_report(analysis_id):
  """Mengambil laporan analisis berdasarkan ID dari VirusTotal."""
  report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
  headers = {"x-apikey": VT_API_KEY}

  # Dalam beberapa kasus, analisis memakan waktu. Kita dapat loop cek status.
  import time
  for _ in range(5):
    resp = requests.get(report_url, headers=headers)
    if resp.status_code == 200:
      data = resp.json()
      status = data.get("data", {}).get("attributes", {}).get("status")
      if status == "completed":
        return data
      else:
        # Tunggu sedikit sebelum coba lagi
        time.sleep(2)
    else:
      print("Error saat mengambil laporan dari VirusTotal:", resp.text)
      break
  return None


def process_virustotal_report(report):
  """Memproses data laporan dari VirusTotal dan mengembalikan embed Discord."""
  attributes = report.get("data", {}).get("attributes", {})
  stats = attributes.get("stats", {})
  malicious = stats.get("malicious", 0)
  suspicious = stats.get("suspicious", 0)
  harmless = stats.get("harmless", 0)
  undetected = stats.get("undetected", 0)

  # Buat embed untuk Discord
  embed = discord.Embed(title="Laporan VirusTotal")
  embed.add_field(name="Malicious", value=str(malicious), inline=True)
  embed.add_field(name="Suspicious", value=str(suspicious), inline=True)
  embed.add_field(name="Harmless", value=str(harmless), inline=True)
  embed.add_field(name="Undetected", value=str(undetected), inline=True)

  # Berikan URL ke laporan detail di VirusTotal
  analysis_id = report.get("data", {}).get("id")
  if analysis_id:
    embed.add_field(
        name="Detail Laporan",
        value=f"https://www.virustotal.com/gui/analysis/{analysis_id}",
        inline=False)

  return embed


# Jalankan bot
bot.run(DISCORD_TOKEN)
